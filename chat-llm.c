#define _GNU_SOURCE // asprintf
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>

#include "chat-llm.h"
#include "alloc-inl.h"
#include "hash.h"

// -lcurl -ljson-c -lpcre2-8
// apt install libcurl4-openssl-dev libjson-c-dev libpcre2-dev libpcre2-8-0

#define MAX_TOKENS 2048
#define CONFIDENT_TIMES 3

struct MemoryStruct
{
    char *memory;
    size_t size;
};

static size_t chat_with_llm_helper(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char *chat_with_llm(char *prompt, char *model, int tries, float temperature)
{
    CURL *curl;
    CURLcode res = CURLE_OK;
    char *answer = NULL;
    char *url = NULL;
    if (strcmp(model, "instruct") == 0)
    {
        url = "https://api.openai-proxy.org/v1/completions";
    }
    else
    {
        url = "https://api.openai-proxy.org/v1/chat/completions";
    }

    char *auth_header = "Authorization: Bearer " OPENAI_TOKEN;
    char *content_header = "Content-Type: application/json";
    char *accept_header = "Accept: application/json";
    char *data = NULL;
    if (strcmp(model, "instruct") == 0)
    {
        asprintf(&data, "{\"model\": \"gpt-3.5-turbo-instruct\", \"prompt\": \"%s\", \"max_tokens\": %d, \"temperature\": %f}", prompt, MAX_TOKENS, temperature);
    }
    else
    {
        asprintf(&data, "{\"model\": \"gpt-3.5-turbo\",\"messages\": %s, \"max_tokens\": %d, \"temperature\": %f}", prompt, MAX_TOKENS, temperature);
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    do
    {
        struct MemoryStruct chunk;

        chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
        chunk.size = 0;           /* no data at this point */

        curl = curl_easy_init();
        if (curl)
        {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, auth_header);
            headers = curl_slist_append(headers, content_header);
            headers = curl_slist_append(headers, accept_header);

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, chat_with_llm_helper);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            res = curl_easy_perform(curl);

            if (res == CURLE_OK)
            {
                json_object *jobj = json_tokener_parse(chunk.memory);

                // Check if the "choices" key exists
                if (json_object_object_get_ex(jobj, "choices", NULL))
                {
                    json_object *choices = json_object_object_get(jobj, "choices");
                    json_object *first_choice = json_object_array_get_idx(choices, 0);
                    const char *data;

                    // The answer begins with a newline character, so we remove it
                    if (strcmp(model, "instruct") == 0)
                    {
                        json_object *jobj4 = json_object_object_get(first_choice, "text");
                        data = json_object_get_string(jobj4);
                    }
                    else
                    {
                        json_object *jobj4 = json_object_object_get(first_choice, "message");
                        json_object *jobj5 = json_object_object_get(jobj4, "content");
                        data = json_object_get_string(jobj5);
                    }
                    if (data[0] == '\n')
                        data++;
                    answer = strdup(data);
                }
                else
                {
                    printf("Error response is: %s\n", chunk.memory);
                    sleep(2); // Sleep for a small amount of time to ensure that the service can recover
                }
                json_object_put(jobj);
            }
            else
            {
                printf("Error: %s\n", curl_easy_strerror(res));
            }

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }

        free(chunk.memory);
    } while ((res != CURLE_OK || answer == NULL) && (--tries > 0));

    if (data != NULL)
    {
        free(data);
    }

    curl_global_cleanup();
    return answer;
}

char *construct_prompt_stall(char *protocol_name, char *examples, char *history)
{
    char *template = "In the %s protocol, the communication history between the %s client and the %s server is as follows."
                     "The next proper client request that can affect the server's state are:\\n\\n"
                     "Desired format of real client requests:\\n%sCommunication History:\\n\\\"\\\"\\\"\\n%s\\\"\\\"\\\"";

    char *prompt = NULL;
    asprintf(&prompt, template, protocol_name, protocol_name, protocol_name, examples, history);

    char *final_prompt = NULL;

    asprintf(&final_prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", prompt);

    free(prompt);

    return final_prompt;
}

char *construct_prompt_for_templates(char *protocol_name, char **final_msg)
{
    // Give one example for learning formats
    char *prompt_rtsp_example = "For the RTSP protocol, the DESCRIBE client request template is:\\n"
                                "DESCRIBE: [\\\"DESCRIBE <<VALUE>>\\\\r\\\\n\\\","
                                "\\\"CSeq: <<VALUE>>\\\\r\\\\n\\\","
                                "\\\"User-Agent: <<VALUE>>\\\\r\\\\n\\\","
                                "\\\"Accept: <<VALUE>>\\\\r\\\\n\\\","
                                "\\\"\\\\r\\\\n\\\"]";

    char *prompt_http_example = "For the HTTP protocol, the GET client request template is:\\n"
                                "GET: [\\\"GET <<VALUE>>\\\\r\\\\n\\\"]";

    char *msg = NULL;
    asprintf(&msg, "%s\\n%s\\nFor the %s protocol, all of client request templates are :", prompt_rtsp_example, prompt_http_example, protocol_name);
    *final_msg = msg;
    /** Format of prompt_grammars
    prompt_grammars = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": msg}
    ]
     **/
    char *prompt_grammars = NULL;

    asprintf(&prompt_grammars, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", msg);

    return prompt_grammars;
}

char *construct_prompt_for_remaining_templates(char *protocol_name, char *first_question, char *first_answer)
{
    char *second_question = NULL;
    asprintf(&second_question, "For the %s protocol, other templates of client requests are:", protocol_name);

    json_object *answer_str = json_object_new_string(first_answer);
    // printf("The First Question\n%s\n\n", first_question);
    // printf("The First Answer\n%s\n\n", first_answer);
    // printf("The Second Question\n%s\n\n", second_question);
    const char *answer_str_escaped = json_object_to_json_string(answer_str);

    char *prompt = NULL;

    asprintf(&prompt,
             "["
             "{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"},"
             "{\"role\": \"user\", \"content\": \"%s\"},"
             "{\"role\": \"assistant\", \"content\": %s },"
             "{\"role\": \"user\", \"content\": \"%s\"}"
             "]",
             first_question, answer_str_escaped, second_question);

    json_object_put(answer_str);
    free(second_question);

    return prompt;
}

char *extract_stalled_message(char *message, size_t message_len)
{

    int errornumber;
    size_t erroroffset;
    // After a lot of iterations, the model consistently responds with an empty line and then a line of text
    pcre2_code *extracter = pcre2_compile("\r?\n?.*?\r?\n", PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(extracter, NULL);
    int rc = pcre2_match(extracter, message, message_len, 0, 0, match_data, NULL);
    char *res = NULL;
    if (rc >= 0)
    {
        size_t *ovector = pcre2_get_ovector_pointer(match_data);
        res = strdup(message + ovector[1]);
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(extracter);

    return res;
}

char *format_request_message(char *message)
{

    int message_len = strlen(message);
    int max_len = message_len;
    int res_len = 0;
    char *res = ck_alloc(message_len * sizeof(char));
    for (int i = 0; i < message_len; i++)
    {
        // If an \n is not padded with an \r before, we add it
        if (message[i] == '\n' && (i == 0 || (message[i - 1] != '\r')))
        {
            if (res_len == max_len)
            {
                res = ck_realloc(res, max_len + 10);
                max_len += 10;
            }
            res[res_len++] = '\r';
        }

        if (res_len == max_len)
        {
            res = ck_realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = message[i];
    }

    // Add \r\n\r\n to ensure that the packet is accepted
    for (int i = 0; i < 2; i++)
    {
        if (res_len == max_len)
        {
            res = ck_realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = '\r';
        if (res_len == max_len)
        {
            res = ck_realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = '\n';
    }

    if (res_len == max_len)
    {
        res = ck_realloc(res, max_len + 1);
        max_len++;
    }
    res[res_len++] = '\0';
    free(message);
    return res;
}

char *construct_prompt_for_protocol_message_types(char *protocol_name)
{
    /***
     * Prompt to ask the protocol states as follow:
     * ```
     * In the RTSP protocol, the protocol states are:
     *
     * Desired format:
     * <comma_separated_list_of_states_in_uppercase>
     * ```
     * ***/
    char *prompt = NULL;

    // transfer the prompt into string
    asprintf(&prompt, "In the %s protocol, the message types are: \\n\\nDesired format:\\n<comma_separated_list_of_states_in_uppercase_and_without_whitespaces>", protocol_name);

    return prompt;
}

char *construct_prompt_for_requests_to_states(const char *protocol_name,
                                              const char *protocol_state,
                                              const char *example_requests)
{
    /***
     Prompt to ask the sequence of client requests to reach a protocol state as follows:
        ```
        In the RTSP protocol, if the server just starts, to reach the PLAYING state, the sequence of client requests can be:
        DESCRIBE rtsp://127.0.0.1:8554/aacAudioTest RTSP/1.0
        CSeq: 2
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Accept: application/sdp

        SETUP rtsp://127.0.0.1:8554/aacAudioTest/track1 RTSP/1.0
        CSeq: 3
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Transport: RTP/AVP;unicast;client_port=38784-38785

        PLAY rtsp://127.0.0.1:8554/aacAudioTest/ RTSP/1.0
        CSeq: 4
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Session: 000022B8
        Range: npt=0.000-

        Similarly, in the RTSP protocol, if the server just starts, to reach the RECORD state, the sequence of client requests can be:
     ***/

    // Transfer formats of example_requests
    json_object *example_requests_json = json_object_new_string(example_requests);
    const char *example_requests_json_str = json_object_to_json_string(example_requests_json);

    json_object *protocol_state_json = json_object_new_string(protocol_state);
    const char *protocol_state_json_str = json_object_to_json_string(protocol_state_json);

    char *prompt = NULL;

    int example_request_len = strlen(example_requests_json_str) - 2;
    if (example_request_len > EXAMPLE_SEQUENCE_PROMPT_LENGTH)
    {
        example_request_len = EXAMPLE_SEQUENCE_PROMPT_LENGTH;
    }

    asprintf(&prompt,
             "In the %s protocol, if the server just starts, to reach the INIT state, the sequence of client requests can be:\\n"
             "%.*s\\nSimilarly, in the %s protocol, if the server just starts, to reach the %.*s state, the sequence of client requests can be:\\n",
             protocol_name,
             example_request_len,
             example_requests_json_str + 1,
             protocol_name,
             (int)strlen(protocol_state_json_str) - 2,
             protocol_state_json_str + 1);

    json_object_put(protocol_state_json);
    json_object_put(example_requests_json);

    return prompt;
}

void extract_message_grammars(char *answers, klist_t(gram) * grammar_list)
{

    char *ptr = answers;
    int len = strlen(answers);

    while (ptr < answers + len)
    {
        char *start = strchr(ptr, '[');
        if (start == NULL)
            break;
        char *end = strchr(start, ']');
        if (end == NULL)
            break;
        int count = end - start + 1;
        char *temp = (char *)ck_alloc(count + 1);
        strncpy(temp, start, count);
        temp[count] = '\0';
        ptr = end + 1;

        // conver temp to json object and save it to the list
        json_object *jobj = json_tokener_parse(temp);
        *kl_pushp(gram, grammar_list) = jobj;

        // printf("%s\n", temp);
    }
}

int parse_pattern(pcre2_code *replacer, pcre2_match_data *match_data, const char *str, size_t len, char *pattern)
{
    strcat(pattern, "(?:");
    // offset == 3;
    int rc = pcre2_match(replacer, str, len, 0, 0, match_data, NULL);

    if (rc < 0)
    {
        switch (rc)
        {
        case PCRE2_ERROR_NOMATCH:
            // printf("No match for %s!\n", str);
            break;
        default:
            // printf("Matching error %d\n", rc);
            break;
        }
        pcre2_match_data_free(match_data);
        pcre2_code_free(replacer);
        return 0;
    }
    // printf("RC is %d\n",rc);
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    // for(int i = 1; i<rc;i++){
    //     printf("Start %d, end %d\n",ovector[2*i],ovector[2*i+1]);
    // }

    if (rc == 4)
    { // matched the first option - there is a special value
        strncat(pattern, str + ovector[2], ovector[3] - ovector[2]);
        // offset += ovector[3] - ovector[2];

        strcat(pattern, "(.*)");
        // offset += 3;

        strncat(pattern, str + ovector[6], ovector[7] - ovector[6]);
        // offset += ovector[7] - ovector[6];
    }
    else if (rc == 5)
    {
        // matched the second option - there is no special value
        strncat(pattern, str + ovector[8], ovector[9] - ovector[8]);
        // offset += ovector[9] - ovector[8];
    }
    else
    {
        FATAL("Regex groups were updated but not the handling code.");
    }
    strcat(pattern, ")");
    return 1;
}

// If successful, puts 2 patterns in the patterns array, the first one is the header, the second is the fields
// Else returns an array with the first element being NULL
char *extract_message_pattern(const char *header_str, khash_t(field_table) * field_table, pcre2_code **patterns, int debug_file, const char *debug_file_name)
{
    int errornumber;
    size_t erroroffset;
    char header_pattern[128] = {0};
    char fields_pattern[1024] = {0};
    pcre2_code *replacer = pcre2_compile("(?:(.*)(?:<<(.*)>>)(.*))|(.+)", PCRE2_ZERO_TERMINATED, PCRE2_DOTALL, &errornumber, &erroroffset, NULL);
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(replacer, NULL);
    char *message_type = NULL;
    // int offset = 0;
    /**
     * Example output
     * patterns[0] = (?:PLAY (.*)\r\n)
     * patterns[1] = (?|(?:CSeq: (.*)\r\n)|(?:User-Agent: (.*)\r\n)|(?:Range: (.*)\r\n)|(?:\r\n))
     */

    {
        // We use the string in such an escaped format for easier debugging as the regex library supports parsing it properly
        // The string contains quotations so they are ignored
        header_str++;

        int message_len = 0;
        while (header_str[message_len] != '\0' 
        && header_str[message_len] != ' ' 
        && header_str[message_len] != '\n' 
        && header_str[message_len] != '\r' 
        && header_str[message_len] != '\\' )
        {
            message_len++;
        }
        message_type = ck_alloc(message_len + 1);
        memcpy(message_type, header_str, message_len);
        message_type[message_len] = '\0';

        size_t len = strlen(header_str) - 1;
        strcat(header_pattern, "^"); // Ensure that it captures the start of the string
        if (!parse_pattern(replacer, match_data, header_str, len, header_pattern))
        {
            patterns[0] = NULL;
            return NULL;
        }
    }

    int first = 1;

    strcat(fields_pattern, "(?|");
    for (khiter_t field_t_iter = kh_begin(field_table); field_t_iter != kh_end(field_table); ++field_t_iter)
    {
        if (!kh_exist(field_table, field_t_iter) || kh_value(field_table, field_t_iter) < (TEMPLATE_CONSISTENCY_COUNT / 2 + (TEMPLATE_CONSISTENCY_COUNT % 2)))
            continue;

        if (!first)
        {
            strcat(fields_pattern, "|");
        }
        else
        {
            first = 0;
        }

        json_object *field_v = json_object_new_string(kh_key(field_table, field_t_iter));
        const char *str = json_object_to_json_string(field_v);
        // We use the string in such an escaped format for easier debugging as the regex library supports parsing it properly
        // The string contains quotations so they are ignored
        str++;
        size_t len = strlen(str) - 1;
        int matched = parse_pattern(replacer, match_data, str, len, fields_pattern);
        json_object_put(field_v);
        if (!matched)
        {
            patterns[0] = NULL;
            return NULL;
        }
    }

    strcat(fields_pattern, ")");

    if (first == 1)
    { // convert from (?|) to (.+) when the group is empty
        fields_pattern[1] = '.';
        fields_pattern[2] = '+';
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(replacer);
    printf("Header pattern is %s\n", header_pattern);
    printf("Fields pattern is %s\n", fields_pattern);

    if (debug_file != -1 && debug_file_name != NULL)
    {
        ck_write(debug_file, header_pattern, strlen(header_pattern), debug_file_name);
        ck_write(debug_file, "\n", 1, debug_file_name);
        ck_write(debug_file, fields_pattern, strlen(fields_pattern), debug_file_name);
    }

    {
        pcre2_code *p = pcre2_compile(header_pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        pcre2_jit_compile(p, PCRE2_JIT_COMPLETE);
        patterns[0] = p;
    }
    {
        pcre2_code *p = pcre2_compile(fields_pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        pcre2_jit_compile(p, PCRE2_JIT_COMPLETE);
        patterns[1] = p;
    }
    return message_type;
}

range_list starts_with(char *line, int length, pcre2_code *pattern)
{
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(pattern, NULL);

    int rc = pcre2_match(pattern, line, length, 0, 0, match_data, NULL); // find the first range

    // printf("starts_with rc is %d\n", rc);
    if (rc < 0)
    {
        switch (rc)
        {
        case PCRE2_ERROR_NOMATCH:
            // printf("No match!\n");
            break;
        default:
            // printf("Matching error %d\n", rc);
            break;
        }
        pcre2_match_data_free(match_data);
        range_list res;
        kv_init(res);
        return res;
    }

    range_list dyn_ranges;
    kv_init(dyn_ranges);
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    for (int i = 1; i < rc; i++)
    {
        if (ovector[2 * i] == -1)
            continue;
        // printf("Group %d %d %d\n",i, ovector[2 * i], ovector[2 * i + 1]);
        range v = {.start = ovector[2 * i], .len = ovector[2 * i + 1] - ovector[2 * i], .mutable = 1};
        kv_push(range, dyn_ranges, v);
        // kv_push(range, dyn_ranges, v);
        //  ranges[0][i - 1] = v;
    }
    range v = {.start = ovector[0], .len = ovector[1] - ovector[0], .mutable = 1};
    kv_push(range, dyn_ranges, v); // add the global range at the end

    pcre2_match_data_free(match_data);
    return dyn_ranges;
}

range_list get_mutable_ranges(char *line, int length, int offset, pcre2_code *pattern)
{
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(pattern, NULL);

    range_list dyn_ranges;
    kv_init(dyn_ranges);

    for (;;) // catch all the other ranges
    {
        int rc = pcre2_match(pattern, line, length, offset, 0, match_data, NULL);
        if (rc < 0)
        {
            switch (rc)
            {
            case PCRE2_ERROR_NOMATCH:
                // printf("No match!\n");
                break;
            default:
                // printf("Matching error %d\n", rc);
                break;
            }
            pcre2_match_data_free(match_data);
            match_data = NULL;
            break;
        }
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        if (offset != ovector[0])
        {
            range v = {.start = offset, .len = ovector[0] - offset, .mutable = 1};
            kv_push(range, dyn_ranges, v);
        }

        // printf("Matched over %d %d\n", ovector[0], ovector[1]);
        for (int i = 1; i < rc; i++)
        {
            if (ovector[2 * i] == -1)
                continue;
            // printf("Group %d %d %d\n",i, ovector[2 * i], ovector[2 * i + 1]);
            range v = {.start = ovector[2 * i], .len = ovector[2 * i + 1] - ovector[2 * i], .mutable = 1};
            kv_push(range, dyn_ranges, v);
            // ranges[0][i - 1] = v;
        }
        if (offset == ovector[1])
        { // in the case the match is empty, we just move a step forward
            offset++;
        }
        else
        {
            offset = ovector[1];
        }
    }

    if (offset < length) // catch anything past the last matched pattern
    {
        range v = {.start = offset, .len = length - offset, .mutable = 1};
        kv_push(range, dyn_ranges, v);
    }

    if (match_data != NULL)
    {
        pcre2_match_data_free(match_data);
    }
    return dyn_ranges;
}

char *unescape_string(const char *input)
{
    size_t length = strlen(input);
    char *output = (char *)malloc((length + 1) * sizeof(char));

    if (output == NULL)
    {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    size_t i, j = 0;
    for (i = 0; i < length; i++)
    {
        if (input[i] == '\\')
        {
            i++; // Skip the backslash
            switch (input[i])
            {
            case 'n':
                output[j++] = '\n';
                break;
            case 't':
                output[j++] = '\t';
                break;
            case 'r':
                output[j++] = '\r';
                break;
            case '\\':
                output[j++] = '\\';
                break;
            default:
                output[j++] = input[i];
                break;
            }
        }
        else
        {
            output[j++] = input[i];
        }
    }

    output[j] = '\0'; // Add null-terminator to the output string
    return output;
}

void write_new_seeds(char *enriched_file, char *contents)
{
    FILE *fp = fopen(enriched_file, "w");
    if (fp == NULL)
    {
        printf("Error in opening the file %s\n", enriched_file);
        exit(1);
    }

    // remove the newline and whiltespace in the beginning of the string if any
    while (contents[0] == '\n' || contents[0] == ' ' || contents[0] == '\t' || contents[0] == '\r')
    {
        contents++;
    }

    // Check if last 4 characters of the client_request_answer string are \r\n\r\n
    // If not, add them
    int len = strlen(contents);
    if (contents[len - 1] != '\n' || contents[len - 2] != '\r' || contents[len - 3] != '\n' || contents[len - 4] != '\r')
    {
        fprintf(fp, "%s\r\n\r\n", contents);
    }
    else
    {
        fprintf(fp, "%s", contents);
    }

    fclose(fp);
}

char *format_string(char *state_string)
{
    // remove the newline and whiltespace in the beginning of the string if any
    while (state_string[0] == '\n' || state_string[0] == ' ' || state_string[0] == '\t' || state_string[0] == '\r')
    {
        state_string++;
    }

    int len = strlen(state_string);
    while (state_string[len - 1] == '\n' || state_string[len - 1] == '\r' || state_string[len - 1] == ' ' || state_string[len - 1] == '.')
    {
        state_string[len - 1] = '\0';
        len--;
    }

    return state_string;
}

/***
 * Get the protocol states based on self-consistency check
 * pass the parameters: protocol_name, states_set, states_string
 ***/
void get_protocol_message_types(char *state_prompt, khash_t(strSet) * states_set)
{
    khash_t(strMap) *state_to_times = kh_init(strMap); // map from state to times

    for (int i = 0; i < CONFIDENT_TIMES; i++)
    {
        char *state_answer = chat_with_llm(state_prompt, "instruct", MESSAGE_TYPE_RETRIES, 0.5);
        if (state_answer == NULL)
            continue;
        // printf("##Answer from LLM:\n %s\n", state_answer);

        state_answer = format_string(state_answer);

        char *state_tokens = strtok(state_answer, ",");
        while (state_tokens != NULL)
        {
            char *protocol_state = state_tokens;
            protocol_state = format_string(protocol_state);
            // save the state to the map
            int ret;
            khiter_t k = kh_put(strMap, state_to_times, protocol_state, &ret);
            if (ret == 0)
            {
                kh_value(state_to_times, k)++;
            }
            else
            {
                kh_value(state_to_times, k) = 1;
            }

            state_tokens = strtok(NULL, ",");
        }
    }

    // traverse the map and get the states whose times are larger than 0.5 * CONFIDENT_TIMES
    for (khiter_t k = kh_begin(state_to_times); k != kh_end(state_to_times); ++k)
    {
        if (kh_exist(state_to_times, k))
        {
            if (kh_value(state_to_times, k) >= 0.5 * CONFIDENT_TIMES)
            {
                const char *protocol_state = kh_key(state_to_times, k);
                // add the state to the set
                int ret;
                kh_put(strSet, states_set, protocol_state, &ret);
            }
        }
    }
}

khash_t(strSet) * duplicate_hash(khash_t(strSet) * set)
{
    khash_t(strSet) *new_set = kh_init(strSet);

    for (khiter_t k = kh_begin(set); k != kh_end(set); ++k)
    {
        if (kh_exist(set, k))
        {
            const char *val = kh_key(set, k);
            int ret;
            kh_put(strSet, new_set, val, &ret);
        }
    }

    return new_set;
}

// message_set_list generate_combinations(khash_t(strSet)* sequence, int size)
// {
//     if(size == 0)
//     {
//         message_set_list output;
//         kv_init(output);
//         kv_push(khash_t(strSet)*,output,kh_init(strSet));
//         return output;
//     }
//     else
//     {
//         message_set_list subcombinations = generate_combinations(sequence,size-1);
//         message_set_list newCombinations;
//         kv_init(newCombinations);
//         for(int i = 0; i < kv_size(subcombinations);i++)
//         {
//             khash_t(strSet)* target = kv_A(subcombinations,i);
//             khiter_t sequence_iter;
//             for (sequence_iter = kh_begin(sequence); sequence_iter != kh_end(sequence); sequence_iter++)
//             {
//                 if (!kh_exist(sequence, sequence_iter))
//                     continue;
//                 khiter_t k = kh_get(strSet, target, kh_val(sequence,sequence_iter));
//                 if (kh_exist(target, k))
//                     continue;
//                 khash_t(strSet)* newCombination = duplicate_hash(target);
//                 int absent;
//                 kh_put(strSet,newCombination,kh_val(sequence,sequence_iter))    
//             }
//         }
//         return newCombinations;
//     }
// }
void make_combination(khash_t(strSet)* sequence, char** data , message_set_list* res,khiter_t st, khiter_t end, int index, int size);

message_set_list message_combinations(khash_t(strSet)* sequence, int size)
{
    message_set_list res;
    kv_init(res);
    char* data[size];
    make_combination(sequence,data, &res, kh_begin(sequence), kh_end(sequence), 0, size);
    return res;
}

void make_combination(khash_t(strSet)* sequence, char** data , message_set_list* res,khiter_t st, khiter_t end,
                     int index, int size)
{

    if (index == size)
    {
        khash_t(strSet)* combination = kh_init(strSet);
        int absent;
        for (int j=0; j<size; j++){
            kh_put(strSet,combination, data[j],&absent );
        }
        kv_push(khash_t(strSet)*,*res,combination);
        return;
    }
    for (khiter_t i=st; i != end && end-i+1 >= size-index; i++)
    {
        if(!kh_exist(sequence,i))
            continue;
        data[index] = kh_key(sequence,i);
        make_combination(sequence, data,res, i+1, end, index+1, size);
    }
}



int min(int a, int b) {
    return a < b ? a : b;
}

char *enrich_sequence(char *sequence, khash_t(strSet) * missing_message_types)
{
    const char *prompt_template =
        "The following is one sequence of client requests:\\n"
        "%.*s\\n"
        "Please add the %.*s client requests in the proper locations, and the modified sequence of client requests is:";

    int missing_fields_len = 0;
    int missing_fields_capacity = 100;
    char *missing_fields_seq = ck_alloc(missing_fields_capacity);

    khiter_t k;
    int i = 0;
    for (k = kh_begin(missing_message_types); 
    k != kh_end(missing_message_types) && i < min(MAX_ENRICHMENT_MESSAGE_TYPES, kh_size(missing_message_types)); 
    ++k)
    {
        if (!kh_exist(missing_message_types, k))
            continue;
        ++i; // Increment only after seeing a message type
        const char *message_type = kh_key(missing_message_types, k);
        int needed_len = strlen(message_type) + 2; // add for the ', '

        if (missing_fields_len + needed_len > missing_fields_capacity)
        {
            missing_fields_capacity += 2 * needed_len;
            missing_fields_seq = ck_realloc(missing_fields_seq, missing_fields_capacity);
        }

        memcpy(missing_fields_seq + missing_fields_len, message_type, strlen(message_type));
        memcpy(missing_fields_seq + missing_fields_len + needed_len - 2, ", ", 2);

        missing_fields_len += needed_len;
    }
    missing_fields_len -= 2; // ignore the last ', '

    char *prompt = NULL;

    json_object *sequence_escaped = json_object_new_string(sequence);
    const char *sequence_escaped_str = json_object_to_json_string(sequence_escaped);
    sequence_escaped_str++;

    int sequence_len = strlen(sequence_escaped_str) - 1;
    int allowed_tokens = (MAX_TOKENS - strlen(prompt_template) - missing_fields_len);
    if (sequence_len > allowed_tokens)
    {
        sequence_len = allowed_tokens;
    }
    asprintf(&prompt, prompt_template, sequence_len, sequence_escaped_str, missing_fields_len, missing_fields_seq);
    ck_free(missing_fields_seq);
    json_object_put(sequence_escaped);

    char *response = chat_with_llm(prompt, "instruct", ENRICHMENT_RETRIES, 0.5);

    free(prompt);

    return response;
}

/* 构建针对特定漏洞的提示词 */
char *construct_vulnerability_prompt(vulnerability_t *vulnerability, const char *protocol_grammar)
{
    char *prompt = NULL;
    char *final_prompt = NULL;
    
    // 如果漏洞提供了特定的提示词模板，优先使用
    if (vulnerability->prompt_template) {
        // 结合协议语法和提示词模板构建最终提示词
        asprintf(&prompt, 
                "Given the %s protocol grammar:\n%s\n\n%s", 
                vulnerability->protocol, 
                protocol_grammar, 
                vulnerability->prompt_template);
    } else {
        // 根据漏洞信息构建通用提示词
        asprintf(&prompt, 
                "Generate a valid %s protocol test case that targets a potential vulnerability.\n\n"
                "Protocol: %s\n"
                "Vulnerable message type: %s\n"
                "Vulnerable field: %s\n"
                "Trigger condition: %s\n"
                "Description: %s\n\n"
                "Protocol grammar reference:\n%s\n\n"
                "Please generate a test case that follows the protocol grammar but contains inputs that might trigger this vulnerability. "
                "Make sure the test case is syntactically valid but contains potentially problematic values for the specified field. "
                "Return ONLY the raw protocol message(s) without any explanation.",
                vulnerability->protocol,
                vulnerability->protocol,
                vulnerability->message_type,
                vulnerability->field_name,
                vulnerability->trigger_condition,
                vulnerability->description,
                protocol_grammar);
    }
    
    // 构建最终的提示词格式
    asprintf(&final_prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant specializing in network protocols and security testing.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", prompt);
    
    free(prompt);
    return final_prompt;
}

/* 使用漏洞信息富集测试用例 */
char *enrich_with_vulnerability(char* sequence, vulnerability_t *vulnerability)
{
    // 提取协议语法 (简化版，实际实现可能需要从已有的语法提取相关部分)
    // 这里假设我们已经有了协议语法的字符串表示
    char *protocol_grammar = strdup(""); // 实际需要填充真实的协议语法
    
    // 构建提示词
    char *prompt = construct_vulnerability_prompt(vulnerability, protocol_grammar);
    
    // 调用LLM生成测试用例
    char *generated_testcase = chat_with_llm(prompt, "gpt", VUL_ENRICHMENT_RETRIES, 0.7);
    
    free(prompt);
    free(protocol_grammar);
    
    return generated_testcase;
}

/* 初始化漏洞模板 */
void init_vulnerability_templates(vulnerability_t *templates, int *template_count)
{
    *template_count = 0;
    
    // RTSP 协议中 Range 字段异常导致缓冲区溢出
    templates[*template_count].vul_name = strdup("RTSP_Range_Overflow");
    templates[*template_count].protocol = strdup("RTSP");
    templates[*template_count].message_type = strdup("PLAY");
    templates[*template_count].field_name = strdup("Range");
    templates[*template_count].trigger_condition = strdup("超长值或特殊格式");
    templates[*template_count].description = strdup("RTSP服务器处理PLAY请求时，如果Range字段格式异常可能导致缓冲区溢出");
    templates[*template_count].prompt_template = strdup(
        "For the RTSP protocol, generate a PLAY request with a malformed or oversized Range field that still follows the basic message structure.\n"
        "Make sure the request looks realistic but may trigger a parser bug due to unusual Range value.\n"
        "Common RTSP Range format is npt=start-end, but try to use extreme values, special characters, or malformed syntax that still appears valid.\n"
        "Return ONLY the raw RTSP protocol message without any explanation."
    );
    (*template_count)++;
    
    // HTTP 协议中 Content-Length 与实际内容不匹配
    templates[*template_count].vul_name = strdup("HTTP_Content_Length_Mismatch");
    templates[*template_count].protocol = strdup("HTTP");
    templates[*template_count].message_type = strdup("POST");
    templates[*template_count].field_name = strdup("Content-Length");
    templates[*template_count].trigger_condition = strdup("与实际内容大小不符");
    templates[*template_count].description = strdup("HTTP服务器在处理POST请求时，如果Content-Length声明与实际内容大小不符可能导致缓冲区溢出或拒绝服务");
    templates[*template_count].prompt_template = strdup(
        "Generate an HTTP POST request where the Content-Length header value doesn't match the actual size of the message body.\n"
        "This can be either much larger or smaller than the actual body size.\n"
        "Include some typical HTTP headers and make the request look realistic.\n"
        "Return ONLY the raw HTTP protocol message without any explanation."
    );
    (*template_count)++;
    
    // FTP协议中的路径遍历漏洞
    templates[*template_count].vul_name = strdup("FTP_Path_Traversal");
    templates[*template_count].protocol = strdup("FTP");
    templates[*template_count].message_type = strdup("CWD");
    templates[*template_count].field_name = strdup("path");
    templates[*template_count].trigger_condition = strdup("包含../等目录遍历字符");
    templates[*template_count].description = strdup("FTP服务器在处理CWD（改变工作目录）命令时，如果路径包含../等字符可能导致目录遍历漏洞");
    templates[*template_count].prompt_template = strdup(
        "Generate an FTP command sequence that attempts to exploit a path traversal vulnerability.\n"
        "Include commands like CWD with path parameters containing sequences like '../' to try accessing files outside the intended directory.\n"
        "Make the sequence look realistic while focusing on directory traversal patterns.\n"
        "Return ONLY the raw FTP protocol commands without any explanation."
    );
    (*template_count)++;
    
    // SMTP命令注入漏洞
    templates[*template_count].vul_name = strdup("SMTP_Command_Injection");
    templates[*template_count].protocol = strdup("SMTP");
    templates[*template_count].message_type = strdup("MAIL FROM");
    templates[*template_count].field_name = strdup("sender");
    templates[*template_count].trigger_condition = strdup("包含换行符或额外命令");
    templates[*template_count].description = strdup("SMTP服务器处理MAIL FROM命令时，如果sender字段包含换行符可能导致命令注入");
    templates[*template_count].prompt_template = strdup(
        "Generate an SMTP session that attempts to exploit a command injection vulnerability.\n"
        "Include a MAIL FROM command where the sender email address contains a newline character followed by an additional SMTP command.\n"
        "Make the sequence look like a valid SMTP conversation but with the injection payload.\n"
        "Return ONLY the raw SMTP protocol commands without any explanation."
    );
    (*template_count)++;
}

/* 释放漏洞模板资源 */
void free_vulnerability_templates(vulnerability_t *templates, int template_count)
{
    for (int i = 0; i < template_count; i++) {
        free(templates[i].vul_name);
        free(templates[i].protocol);
        free(templates[i].message_type);
        free(templates[i].field_name);
        free(templates[i].trigger_condition);
        free(templates[i].description);
        free(templates[i].prompt_template);
    }
}

/* 验证生成的测试用例的语法正确性 */
int validate_generated_testcase(char *testcase, const char *protocol)
{
    // 这里应该实现根据协议类型进行不同的验证逻辑
    // 简单实现：检查是否为空，以及包含一些基本的协议关键字
    
    if (!testcase || strlen(testcase) < 5) {
        return 0; // 太短，无效
    }
    
    // 根据协议类型进行简单验证
    if (strcmp(protocol, "RTSP") == 0) {
        return (strstr(testcase, "RTSP/1.0") != NULL);
    } else if (strcmp(protocol, "HTTP") == 0) {
        return (strstr(testcase, "HTTP/1.") != NULL);
    } else if (strcmp(protocol, "FTP") == 0) {
        return (strstr(testcase, "CWD") != NULL || strstr(testcase, "USER") != NULL);
    } else if (strcmp(protocol, "SMTP") == 0) {
        return (strstr(testcase, "MAIL FROM") != NULL || strstr(testcase, "HELO") != NULL);
    }
    
    return 1; // 默认认为有效（保守策略）
}

/* 获取由历史漏洞驱动的测试用例种子 */
void get_vulnerability_driven_seeds(const char *in_dir, vulnerability_t *templates, int template_count)
{
    struct dirent **nl_files;
    int nl_cnt = scandir(in_dir, &nl_files, NULL, alphasort);
    
    if (nl_cnt < 0) {
        printf("Error reading directory %s\n", in_dir);
        return;
    }
    
    ACTF("Generating vulnerability-driven test cases...");
    
    // 遍历每个漏洞模板
    for (int t = 0; t < template_count; t++) {
        vulnerability_t *current_vul = &templates[t];
        
        // 为每个漏洞模板生成至少一个测试用例
        char *generated_testcase = enrich_with_vulnerability(NULL, current_vul);
        
        if (generated_testcase && validate_generated_testcase(generated_testcase, current_vul->protocol)) {
            // 创建新的种子文件
            char *vul_seed_name = alloc_printf("vul_%s.raw", current_vul->vul_name);
            char *vul_seed_path = alloc_printf("%s/%s", in_dir, vul_seed_name);
            
            ACTF("Creating vulnerability-driven seed: %s", vul_seed_name);
            write_new_seeds(vul_seed_path, generated_testcase);
            
            ck_free(vul_seed_name);
            ck_free(vul_seed_path);
        }
        
        free(generated_testcase);
        
        // 对现有种子进行富集
        for (int i = 0; i < MIN(nl_cnt, 5); i++) { // 限制处理前5个种子
            char *nl_file_name = nl_files[i]->d_name;
            
            // 跳过特殊文件和已富集文件
            if (strcmp(nl_file_name, ".") == 0 || strcmp(nl_file_name, "..") == 0 || 
                strstr(nl_file_name, "enriched") != NULL || strstr(nl_file_name, "vul_") != NULL) {
                continue;
            }
            
            char *nl_file_path = alloc_printf("%s/%s", in_dir, nl_file_name);
            
            // 读取种子文件内容
            FILE *nl_file = fopen(nl_file_path, "r");
            if (!nl_file) {
                ck_free(nl_file_path);
                continue;
            }
            
            fseek(nl_file, 0, SEEK_END);
            size_t fsize = ftell(nl_file);
            fseek(nl_file, 0, SEEK_SET);
            
            char *nl_file_content = ck_alloc(fsize + 1);
            fread(nl_file_content, fsize, 1, nl_file);
            nl_file_content[fsize] = '\0';
            fclose(nl_file);
            
            // 使用当前漏洞模板富集种子
            char *enriched_testcase = enrich_with_vulnerability(nl_file_content, current_vul);
            
            if (enriched_testcase && 
                validate_generated_testcase(enriched_testcase, current_vul->protocol) && 
                strcmp(format_string(enriched_testcase), format_string(nl_file_content)) != 0) {
                
                // 创建富集后的种子文件
                char *enriched_name = alloc_printf("vul_%s_%s", current_vul->vul_name, nl_file_name);
                char *enriched_path = alloc_printf("%s/%s", in_dir, enriched_name);
                
                ACTF("Creating vulnerability-enriched seed: %s", enriched_name);
                write_new_seeds(enriched_path, enriched_testcase);
                
                ck_free(enriched_name);
                ck_free(enriched_path);
            }
            
            free(enriched_testcase);
            ck_free(nl_file_content);
            ck_free(nl_file_path);
        }
    }
    
    // 释放资源
    for (int i = 0; i < nl_cnt; i++) {
        free(nl_files[i]);
    }
    free(nl_files);
}
