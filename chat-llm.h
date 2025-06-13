#ifndef __CHAT_LLM_H
#define __CHAT_LLM_H

#include "klist.h"
#include "kvec.h"
#include "khash.h"
#include <json-c/json.h>

/*
There are 2048 tokens available, around 270 are used for the initial data for the stall prompt
We give at most 400 for the examples and 1300 for the stall prompt
Similarly 1700 is for the example request in the seed enrichment
*/

#define OPENAI_TOKEN "your-api-key"

#define MAX_PROMPT_LENGTH 2048
#define EXAMPLES_PROMPT_LENGTH 400
#define HISTORY_PROMPT_LENGTH 1300
#define EXAMPLE_SEQUENCE_PROMPT_LENGTH 1700

#define TEMPLATE_CONSISTENCY_COUNT 3

// Maximum amount of retries for the state stall
#define STALL_RETRIES 2

// Maximum amount of tries to get the grammars
#define GRAMMAR_RETRIES 3

// Maximum amount
#define MESSAGE_TYPE_RETRIES 3

//Maximum amount of tries for an enrichment
#define ENRICHMENT_RETRIES 3

// Maximum number of messages to be added
#define MAX_ENRICHMENT_MESSAGE_TYPES 2

// Maximum number of messages to examine for addition
#define MAX_ENRICHMENT_CORPUS_SIZE 10

// 漏洞驱动用例生成的重试次数
#define VUL_ENRICHMENT_RETRIES 3

// 每个协议最大漏洞模板数量
#define MAX_VUL_TEMPLATES 50

// 历史漏洞描述结构体
typedef struct vulnerability_template {
    char* name;
    char* description;
    char* pattern;
    char* applicable_message_types;
} vulnerability_t;

#define PCRE2_CODE_UNIT_WIDTH 8 // Characters are 8 bits
#include <pcre2.h>

// Init KLIST with JSON object
#define __grammar_t_free(x)
#define __rang_t_free(x)
#define __khash_t_free(x) 
KHASH_SET_INIT_STR(strSet);
KLIST_INIT(gram, json_object *, __grammar_t_free)
KLIST_INIT(rang, pcre2_code **, __rang_t_free)
typedef struct
{
    int start;
    int len;
    int mutable;
} range;

// 使用单一结构体表示漏洞模式
typedef struct {
    char* name;             // 漏洞名称
    char* description;      // 描述
    char* target_messages;  // 目标消息类型
    char* pattern;          // 漏洞模式
} vuln_pattern_t;

typedef kvec_t(range) range_list;
typedef kvec_t(khash_t(strSet)*) message_set_list;

// 定义漏洞模式的 klist 结构体
#define __vuln_pattern_t_free(x) do { \
    if ((x)->data) { \
        free(((x)->data)->description); \
        free(((x)->data)->target_messages); \
        free(((x)->data)->pattern); \
        free((x)->data); \
    } \
} while(0)
KLIST_INIT(vuln_patterns, vuln_pattern_t*, __vuln_pattern_t_free);

// 定义一个 map 结构体，保存 {key: string, value: int} 的键值对
KHASH_MAP_INIT_STR(strMap, int)
KHASH_MAP_INIT_STR(field_table, int);
KHASH_INIT(consistency_table, const char *, khash_t(field_table) *, 1, kh_str_hash_func, kh_str_hash_equal);

// 定义一个 map 结构体，保存 {key: 协议名称（字符串），value: 列表漏洞模式} 的键值对
KHASH_MAP_INIT_STR(vuln_map, klist_t(vuln_patterns)*);

// 声明外部变量
extern char* protocol_name;
extern khash_t(vuln_map)* vuln_patterns_map;

// 用于构建漏洞感知提示的新函数原型
char* construct_prompt_for_vuln_enrichment(const char* sequence, const char* message_type_to_add, vuln_pattern_t* pattern);

char *chat_with_llm(char *prompt, char *model, int tries, float temperature);
char *construct_prompt_for_templates(char *protocol_name, char **final_msg);
char *construct_prompt_for_remaining_templates(char *protocol_name, char *templates_prompt, char *templates_answer);
char *construct_prompt_for_protocol_message_types(char *protocol_name);
char *construct_prompt_for_requests_to_states(const char *protocol_name, const char *protocol_state, const char *example_requests);
char *construct_prompt_stall(char *protocol_name, char *examples, char *history);
char *construct_vulnerability_prompt(vulnerability_t *vulnerability, const char *protocol_grammar);

void extract_message_grammars(char *answers, klist_t(gram) * grammar_set);
char *extract_message_pattern(const char *header_str,
                               khash_t(field_table) * field_table,
                               pcre2_code **patterns,
                               int debug_file,
                               const char *debug_file_name);
char *extract_stalled_message(char *message, size_t message_len);
char *format_request_message(char *message);


range_list starts_with(char *line, int length, pcre2_code *pattern);
range_list get_mutable_ranges(char *line, int length, int offset, pcre2_code *pattern);
void get_protocol_message_types(char *state_prompt, khash_t(strSet) * message_types);

char *enrich_with_vulnerability(char* sequence, vulnerability_t *vulnerability);
char *enrich_sequence_generic(char* sequence, khash_t(strSet) *missing_message_types);
char *enrich_sequence_with_vuln_pattern(char* sequence, const char* message_type, vuln_pattern_t* pattern);

khash_t(strSet)* duplicate_hash(khash_t(strSet)* set);
void write_new_seeds(char *enriched_file, char *contents);
char *unescape_string(const char *input);
char *format_string(char *state_string);
message_set_list message_combinations(khash_t(strSet)* sequence, int size);

// 漏洞驱动用例富集相关函数
int validate_generated_testcase(char *testcase, const char *protocol);
void get_vulnerability_driven_seeds(const char *in_dir, vulnerability_t *templates, int template_count);

// 更新函数声明，使用 char** 而不是 const char**
void make_combination(khash_t(strSet)* sequence, char** data, message_set_list* res, khiter_t st, khiter_t end, int index, int size);

// 添加最大模式大小常量
#define MAX_PATTERN_SIZE (64 * 1024)  // 64KB 应该足够大

#endif // __CHAT_LLM_H
