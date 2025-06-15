#define _GNU_SOURCE // asprintf
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "chat-llm.h"
#include "alloc-inl.h"
#include "hash.h"
#include "types.h"
#include "debug.h"
#include "khash.h"

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


char* construct_prompt_for_vuln_enrichment(const char* sequence, const char* message_type_to_add, vuln_pattern_t* pattern) {
    if (!sequence || !message_type_to_add || !pattern) return NULL;
    
    const char* prompt_template =
        "ROLE: You are a cyber-security assistant specialised in generating network protocol test cases.\n"
        "TASK: Inject the given vulnerability pattern into the sequence **without breaking protocol syntax**.\n"
        "RULES:\n"
        "1. Preserve \\r\\n line terminators exactly.\n"
        "2. Modify or insert **one %s request** so the payload matches the PATTERN.\n"
        "3. Do NOT reorder existing messages unless necessary.\n"
        "4. Output ONLY the full modified sequence, no comments, no Markdown.\n\n"
        "=== CURRENT SEQUENCE START ===\n%s\n=== CURRENT SEQUENCE END ===\n\n"
        "=== VULNERABILITY DESCRIPTION ===\n%s\n"
        "=== PATTERN TO INJECT ===\n%s\n"
        "=== END ===";
    
    // 使用json-c库正确处理JSON转义
    json_object *seq_json = json_object_new_string(sequence);
    json_object *msg_type_json = json_object_new_string(message_type_to_add);
    json_object *desc_json = json_object_new_string(pattern->description ? pattern->description : "");
    json_object *pattern_json = json_object_new_string(pattern->pattern ? pattern->pattern : "");
    
    const char *seq_escaped = json_object_get_string(seq_json);
    const char *msg_type_escaped = json_object_get_string(msg_type_json);
    const char *desc_escaped = json_object_get_string(desc_json);
    const char *pattern_escaped = json_object_get_string(pattern_json);
    
    // 计算所需空间并分配
    int estimated_size = strlen(prompt_template) + 
                        strlen(seq_escaped) + 
                        strlen(desc_escaped) + 
                        strlen(pattern_escaped) + 
                        strlen(msg_type_escaped) + 100; // 额外空间用于安全性
                        
    char* prompt = (char*)malloc(estimated_size);
    if (!prompt) {
        json_object_put(seq_json);
        json_object_put(msg_type_json);
        json_object_put(desc_json);
        json_object_put(pattern_json);
        return NULL;
    }
    
    snprintf(prompt, estimated_size, prompt_template,
            msg_type_escaped,
            seq_escaped,
            desc_escaped,
            pattern_escaped);
            
    // 释放JSON对象
    json_object_put(seq_json);
    json_object_put(desc_json);
    json_object_put(pattern_json);
    json_object_put(msg_type_json);
            
    return prompt;
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
    // printf("Header pattern is %s\n", header_pattern);        //For debug
    // printf("Fields pattern is %s\n", fields_pattern);        //For debug

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

/*
 * Helper function to create directories recursively
 */
void create_directory_recursive(const char *path) {
    if (!path || strlen(path) == 0) return;
    
    char *path_copy = strdup(path);
    if (!path_copy) return;
    
    // 统一使用系统适合的分隔符
    #ifdef _WIN32
    char separator = '\\';
    #else
    char separator = '/';
    #endif
    
    // 替换所有分隔符为系统适合的分隔符
    for (char *p = path_copy; *p; p++) {
        if (*p == '/' || *p == '\\') *p = separator;
    }
    
    // 创建目录层次
    for (char *p = path_copy + 1; *p; p++) {
        if (*p == separator) {
            *p = '\0';
            
            #ifdef _WIN32
            mkdir(path_copy);
            #else
            if (mkdir(path_copy, 0700) != 0 && errno != EEXIST) {
                fprintf(stderr, "Failed to create directory %s: %s\n", path_copy, strerror(errno));
            }
            #endif
            
            *p = separator;
        }
    }
    
    // 创建最终目录
    #ifdef _WIN32
    mkdir(path_copy);
    #else
    if (mkdir(path_copy, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path_copy, strerror(errno));
    }
    #endif
    
    free(path_copy);
}

void write_new_seeds(char *enriched_file, char *contents)
{
    // Create parent directories if they don't exist
    char *parent_dir = strdup(enriched_file);
    if (parent_dir) {
        char *last_slash = strrchr(parent_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            create_directory_recursive(parent_dir);
        }
        free(parent_dir);
    }
    
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
        // printf("## Answer from LLM:\n %s\n", state_answer);

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

char *enrich_sequence(char *sequence, khash_t(strSet) *missing_message_types)
{
    if (!sequence || !missing_message_types || kh_size(missing_message_types) == 0)
        return NULL;

    /* -------------------------------------------------------------
       1. 首先尝试使用漏洞模式进行富集
    ------------------------------------------------------------- */
    if (vuln_patterns_map && protocol_name) {
        khiter_t k_proto = kh_get(vuln_map, vuln_patterns_map, protocol_name);
        if (k_proto != kh_end(vuln_patterns_map)) {
            klist_t(vuln_patterns) *patterns = kh_value(vuln_patterns_map, k_proto);

            /* 遍历缺失的消息类型，寻找匹配的漏洞模式 */
            for (khiter_t kmiss = kh_begin(missing_message_types); kmiss != kh_end(missing_message_types); ++kmiss)
            {
                if (!kh_exist(missing_message_types, kmiss))
                    continue;

                const char *message_type = kh_key(missing_message_types, kmiss);

                /* 遍历所有漏洞模式，查找以该消息类型为目标的模式（或通配符*） */
                kliter_t(vuln_patterns) *it;
                for (it = kl_begin(patterns); it != kl_end(patterns); it = kl_next(it))
                {
                    vuln_pattern_t *p = kl_val(it);
                    if (!p || !p->target_messages)
                        continue;

                    char *targets_copy = ck_strdup(p->target_messages);
                    char *token = strtok(targets_copy, ",");
                    int matched = 0;
                    while (token)
                    {
                        /* 去除首尾空格 */
                        while (isspace(*token))
                            token++;
                        if (strcmp(token, "*") == 0 || strcasecmp(token, message_type) == 0)
                        {
                            matched = 1;
                            break;
                        }
                        token = strtok(NULL, ",");
                    }
                    ck_free(targets_copy);

                    if (!matched)
                        continue;

                    /* 构造提示词并调用 LLM 进行富集 */
                    char *prompt = construct_prompt_for_vuln_enrichment(sequence, message_type, p);
                    if (!prompt)
                        continue;

                    char *response = chat_with_llm(prompt, "turbo", ENRICHMENT_RETRIES, 0.7);
                    free(prompt);

                    if (response && strlen(response) > 0)
                    {
                        OKF("Vulnerability-driven enrichment for message type '%s' succeeded.", message_type);
                        return response; /* 成功返回 */
                    }
                }
            }
        }
    }

    /* -------------------------------------------------------------
       2.  若没有任何漏洞模式匹配，回退到原有的通用富集逻辑
    ------------------------------------------------------------- */

    const char *prompt_template =
        "The following is one sequence of client requests:\n"
        "%.*s\n"
        "Please add the %.*s client requests in the proper locations, and the modified sequence of client requests is:";

    int missing_fields_len = 0;
    int missing_fields_capacity = 100;
    char *missing_fields_seq = ck_alloc(missing_fields_capacity);

    /* 将缺失的消息类型列表拼接成逗号分隔字符串 */
    int collected = 0;
    for (khiter_t k = kh_begin(missing_message_types);
         k != kh_end(missing_message_types) && collected < MAX_ENRICHMENT_MESSAGE_TYPES; ++k)
    {
        if (!kh_exist(missing_message_types, k))
            continue;

        const char *msg_type = kh_key(missing_message_types, k);
        int needed = strlen(msg_type) + 2; /* 加上", " */

        if (missing_fields_len + needed > missing_fields_capacity)
        {
            missing_fields_capacity += 2 * needed;
            missing_fields_seq = ck_realloc(missing_fields_seq, missing_fields_capacity);
        }

        memcpy(missing_fields_seq + missing_fields_len, msg_type, strlen(msg_type));
        memcpy(missing_fields_seq + missing_fields_len + needed - 2, ", ", 2);
        missing_fields_len += needed;
        collected++;
    }
    if (missing_fields_len >= 2)
        missing_fields_len -= 2; /* 移除最后一个", " */

    /* 使用json-c库正确处理JSON转义 */
    json_object *seq_json = json_object_new_string(sequence);
    json_object *missing_fields_json = json_object_new_string(missing_fields_seq);
    
    const char *seq_escaped = json_object_get_string(seq_json);
    const char *missing_fields_escaped = json_object_get_string(missing_fields_json);
    
    /* 创建提示词 */
    char *prompt_template_full = "The following is one sequence of client requests:\n%s\nPlease add the %s client requests in the proper locations, and the modified sequence of client requests is:";
    
    char *prompt = NULL;
    asprintf(&prompt, prompt_template_full, seq_escaped, missing_fields_escaped);

    ck_free(missing_fields_seq);
    json_object_put(seq_json);
    json_object_put(missing_fields_json);

    char *response = chat_with_llm(prompt, "instruct", ENRICHMENT_RETRIES, 0.5);
    free(prompt);

    return response;
}

/* 
 * 实现基于漏洞模式的序列富集函数
 * 这个函数在afl-fuzz.c中被调用，但原来缺少实现
 */
char *enrich_sequence_with_vuln_pattern(char *sequence, const char *message_type, vuln_pattern_t *pattern)
{
    if (!sequence || !message_type || !pattern || !pattern->pattern) return NULL;

    // 构造提示词
    char *prompt = construct_prompt_for_vuln_enrichment(sequence, message_type, pattern);
    if (!prompt) return NULL;

    // 记录调试信息
    ACTF("Attempting to enrich sequence with vulnerability pattern for message type %s", message_type);
    
    // 设置重试次数限制，避免无限循环
    int max_tries = 2; // 减少重试次数，避免长时间卡住
    
    // 调用LLM生成富集结果
    char *response = chat_with_llm(prompt, "turbo", max_tries, 0.7);
    free(prompt);

    // 记录结果
    if (response) {
        OKF("Successfully enriched sequence with %s vulnerability pattern", 
             pattern->name ? pattern->name : "unknown");
    } else {
        WARNF("Failed to enrich sequence with vulnerability pattern");
    }

    return response;
}

/*
 * 实现测试用例验证函数
 * 这个函数在afl-fuzz.c中被调用，但原来缺少实现
 */
int validate_generated_testcase(char *testcase, const char *protocol)
{
    if (!testcase || !protocol) return 0;
    
    // 基本检查
    size_t len = strlen(testcase);
    
    // 1. 检查是否为空
    if (len < 10) {
        WARNF("Generated testcase too short (%zu bytes)", len);
        return 0;
    }
    
    // 记录调试信息
    ACTF("Validating generated testcase (%zu bytes) for protocol %s", len, protocol);
    
    // 2. 检查文本协议的行结束符
    if (strcasecmp(protocol, "http") == 0 || 
        strcasecmp(protocol, "smtp") == 0 || 
        strcasecmp(protocol, "rtsp") == 0 || 
        strcasecmp(protocol, "ftp") == 0 ||
        strcasecmp(protocol, "sip") == 0) {
        
        // 检查CRLF，但不强制要求（有些LLM可能生成\n而非\r\n）
        if (strstr(testcase, "\r\n") == NULL && strstr(testcase, "\n") == NULL) {
            WARNF("Generated %s testcase missing any line endings", protocol);
            return 0;
        }
        
        // 协议特定检查
        if (strcasecmp(protocol, "http") == 0 && 
            (!strstr(testcase, "HTTP/") && !strstr(testcase, "GET ") && 
             !strstr(testcase, "POST ") && !strstr(testcase, "PUT "))) {
            WARNF("Generated HTTP testcase missing basic HTTP method or version");
            return 0;
        }
        else if (strcasecmp(protocol, "rtsp") == 0 && !strstr(testcase, "RTSP/")) {
            WARNF("Generated RTSP testcase missing RTSP version");
            return 0;
        }
    }
    
    // 通过基本验证
    OKF("Testcase validation passed");
    return 1;
}

/*
 * Implementation of vulnerability template initialization and cleanup functions
 */
void init_vulnerability_templates(vulnerability_t *templates, int *template_count) {
    if (!templates || !template_count) return;
    
    // Initialize all templates to NULL values
    for (int i = 0; i < MAX_VUL_TEMPLATES; i++) {
        templates[i].name = NULL;
        templates[i].description = NULL;
        templates[i].pattern = NULL;
        templates[i].applicable_message_types = NULL;
    }
    
    *template_count = 0;
}

void free_vulnerability_templates(vulnerability_t *templates, int template_count) {
    if (!templates) return;
    
    for (int i = 0; i < template_count; i++) {
        if (templates[i].name) {
            free(templates[i].name);
            templates[i].name = NULL;
        }
        if (templates[i].description) {
            free(templates[i].description);
            templates[i].description = NULL;
        }
        if (templates[i].pattern) {
            free(templates[i].pattern);
            templates[i].pattern = NULL;
        }
        if (templates[i].applicable_message_types) {
            free(templates[i].applicable_message_types);
            templates[i].applicable_message_types = NULL;
        }
    }
}

int main() {
    vuln_patterns_map = kh_init(vuln_map);
    if (!vuln_patterns_map) {
        FATAL("Failed to initialize vulnerability patterns map");
    }

    // ... rest of the main function ...

    if (vuln_patterns_map) {
        // 遍历并释放所有漏洞模式
        for (khiter_t k = kh_begin(vuln_patterns_map); k != kh_end(vuln_patterns_map); ++k) {
            if (kh_exist(vuln_patterns_map, k)) {
                klist_t(vuln_patterns) *patterns = kh_value(vuln_patterns_map, k);
                if (patterns) {
                    kl_destroy(vuln_patterns, patterns);
                }
            }
        }
        kh_destroy(vuln_map, vuln_patterns_map);
    }

    return 0;
}