/* 定义程序全局变量 */
/* 以太网帧头部结构体定义 */
/* 定义程序辅助函数 */

#pragma once
#include <pcap.h>
#include <winsock2.h>
#include <conio.h>
#include <string>
#include <sstream>
#include <cctype>

struct ether_header {
	u_char ether_dhost[6];         // 目标MAC地址
	u_char ether_shost[6];         // 源MAC地址
	u_short ether_type;            // 以太网类型
};

struct EtherTypeEntry {
    const char* name;
    u_short value;
};

enum PostSendAction {
    SEND_AGAIN_SAME_ALL = 1,
    SEND_AGAIN_SAME_MACS_NEW_INTERFACE = 2,
    RESTART_ALL = 3,
    EXIT_PROGRAM = 4
};

struct MacPair {  
   u_char dest[6] = {0};  // 初始化目标MAC地址  
   u_char src[6] = {0};   // 初始化源MAC地址  
   bool valid = false;  
};

struct PayloadConfig {
    u_char data[1500]; // 最大支持1500字节
    int length = 0;
    bool enabled = false;

    PayloadConfig() : length(0), enabled(false) {
        memset(data, 0, sizeof(data));
    }
};

PostSendAction ethertype_selection_interface(pcap_t* adhandle,
    const u_char* original_dest,
    const u_char* original_src,
    const char* interface_desc
);

const DWORD INPUT_TIMEOUT_MS = 15000;    // 输入操作超时时间（15秒）
const DWORD MESSAGE_WAIT_SECONDS = 10;   // 消息等待时间（10秒）
static u_char packet_buffer[1514] = { 0 }; // 以太网帧缓冲区（最大1514字节）


inline bool timed_get_input_line(char* buffer, int buffer_size, DWORD timeout_ms) {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD start_time = GetTickCount64();

    DWORD waitResult = WaitForSingleObject(hInput, timeout_ms);

    if (waitResult == WAIT_OBJECT_0) {
        if (fgets(buffer, buffer_size, stdin)) {
            buffer[strcspn(buffer, "\n")] = 0;
            return true;
        }
    }
    printf("\n输入超时！请重新输入。\n");
    return false; // 超时或错误
}

// 解析MAC地址字符串（支持冒号、连字符或无分隔符格式）
inline bool parse_mac_address(const char* mac_str, u_char* mac_addr) {
    int values[6]{};
    int result = sscanf_s(mac_str, "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]);
    if (result == 6) {
        for (int i = 0; i < 6; ++i) {
            if (values[i] < 0 || values[i] > 255) return false;
            mac_addr[i] = (u_char)values[i];
        }
        return true;
    }

    // 尝试连字符分隔
    result = sscanf_s(mac_str, "%x-%x-%x-%x-%x-%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]);
    if (result == 6) {
        for (int i = 0; i < 6; ++i) {
            if (values[i] < 0 || values[i] > 255) return false;
            mac_addr[i] = (u_char)values[i];
        }
        return true;
    }

    // 尝试无分隔符（12位十六进制）
    if (strlen(mac_str) == 12) {
        result = sscanf_s(mac_str, "%2x%2x%2x%2x%2x%2x",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5]);
        if (result == 6) {
            for (int i = 0; i < 6; ++i) {
                mac_addr[i] = (u_char)values[i];
            }
            return true;
        }
    }
    return false; // 所有解析尝试都失败
}

inline std::string format_payload_status(const PayloadConfig& payload) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d字节 [%02X %02X...]",
        payload.length,
        payload.data[0],
        payload.data[1]);
    return buf;
}

inline bool input_payload(PayloadConfig& payload) {
    payload = PayloadConfig(); // 重置 payload 状态

    printf("\n=== Payload 输入 ===\n");
    printf("支持格式：\n");
    printf("1. 十六进制 (例: AA BB CC 或 AABBCC)\n");
    printf("2. ASCII 字符串 (例: Hello!)\n");
    printf("3. 随机生成\n");

    int choice_num = 0;
    bool choice_ok = false;
    DWORD start_time_choice = GetTickCount64();
    DWORD time_limit_choice = INPUT_TIMEOUT_MS;

    // --- 循环获取并验证输入方式 ---
    while (GetTickCount64() - start_time_choice < time_limit_choice && !choice_ok) {
        DWORD remaining_time = time_limit_choice - (GetTickCount64() - start_time_choice);
        if ((long)remaining_time <= 0) break; // 超时检查

        printf("请选择输入方式 (1-3) [%lu ms remaining]: ", remaining_time);
        char choice_buf[10] = { 0 };
        if (!timed_get_input_line(choice_buf, sizeof(choice_buf), remaining_time)) {
            printf("\n输入超时！\n");
            return false; // 输入超时，函数失败
        }

        // 验证输入是否为单个数字 1, 2, 或 3
        if (strlen(choice_buf) == 1 && isdigit(choice_buf[0])) {
            choice_num = atoi(choice_buf);
            if (choice_num >= 1 && choice_num <= 3) {
                choice_ok = true; // 输入有效
            }
            else {
                printf("错误：无效的输入方式编号！请重试。\n");
            }
        }
        else {
            printf("错误：请输入单个数字 (1-3)！请重试。\n");
        }
    }

    if (!choice_ok) {
        printf("选择输入方式超时或失败！\n");
        return false; // 未能在超时前选择有效方式
    }

    // --- 根据选择处理 Payload ---
    bool payload_input_ok = false;
    switch (choice_num) {
    case 1: { // 十六进制输入
        printf("请输入十六进制数据 (空格分隔或连续输入, 最多 1500 字节):\n");
        DWORD start_time_hex = GetTickCount64();
        DWORD time_limit_hex = INPUT_TIMEOUT_MS;

        while (GetTickCount64() - start_time_hex < time_limit_hex && !payload_input_ok) {
            DWORD remaining_time = time_limit_hex - (GetTickCount64() - start_time_hex);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[3001] = { 0 }; // 1500 bytes * 2 chars/byte + spaces/null
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n输入超时！\n");
                return false;
            }

            if (strlen(input_buf) == 0) {
                printf("错误：未输入任何数据！请重试。\n");
                continue; // 重新提示输入
            }

            // 解析十六进制数据
            payload.length = 0; // 重置计数器以便重试
            std::string hex_string = input_buf;
            std::string current_byte_str;
            bool parse_error = false;

            for (size_t i = 0; i < hex_string.length() && payload.length < 1500; ) {
                // 跳过空格
                if (isspace(hex_string[i])) {
                    i++;
                    continue;
                }
                // 读取 1 或 2 个十六进制字符
                current_byte_str = "";
                if (i < hex_string.length() && isxdigit(hex_string[i])) {
                    current_byte_str += hex_string[i];
                    i++;
                    if (i < hex_string.length() && isxdigit(hex_string[i])) {
                        current_byte_str += hex_string[i];
                        i++;
                    }
                }
                else {
                    // 非十六进制字符或空格
                    printf("错误：在位置 %zu 遇到无效字符 '%c'。请重新输入整行。\n", i, hex_string[i]);
                    parse_error = true;
                    break;
                }


                // 转换当前字节
                try {
                    unsigned long byte_val = std::stoul(current_byte_str, nullptr, 16);
                    if (byte_val > 255) { // Should not happen with 1 or 2 hex digits, but check
                        printf("错误：解析字节 '%s' 时出错。请重新输入整行。\n", current_byte_str.c_str());
                        parse_error = true;
                        break;
                    }
                    payload.data[payload.length++] = static_cast<u_char>(byte_val);
                }
                catch (const std::invalid_argument& ia) {
                    printf("错误：无法将 '%s' 解析为十六进制。请重新输入整行。\n", current_byte_str.c_str());
                    parse_error = true;
                    break;
                }
                catch (const std::out_of_range& oor) {
                    printf("错误：字节值 '%s' 超出范围。请重新输入整行。\n", current_byte_str.c_str());
                    parse_error = true;
                    break;
                }
            }

            if (parse_error) {
                payload.length = 0; // 解析出错，重置长度
                continue; // 提示用户重新输入
            }

            if (payload.length > 0) {
                payload_input_ok = true; // 成功获取非空 payload
                if (payload.length >= 1500) {
                    printf("警告：已达到 Payload 最大长度 (1500 字节)。\n");
                }
            }
            else if (strlen(input_buf) > 0 && !parse_error) {
                // 输入非空，但解析后长度为 0 (例如输入了只有空格)
                printf("错误：未解析到有效的十六进制数据！请重试。\n");
                // 让循环继续以重试
            }
           
        }

        if (!payload_input_ok) {
            printf("输入十六进制数据超时或未能成功解析！\n");
            return false; // 未能在超时前输入有效 hex
        }
        break;
    }

    case 2: { // ASCII 输入
        printf("请输入文本 (最大 1500 字符):\n");
        DWORD start_time_ascii = GetTickCount64();
        DWORD time_limit_ascii = INPUT_TIMEOUT_MS;

        while (GetTickCount64() - start_time_ascii < time_limit_ascii && !payload_input_ok) {
            DWORD remaining_time = time_limit_ascii - (GetTickCount64() - start_time_ascii);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[1501] = { 0 };
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n输入超时！\n");
                return false;
            }

            if (strlen(input_buf) == 0) {
                printf("提示：输入为空字符串。\n");
                payload.length = 0;
                payload_input_ok = true; // 认为空字符串是有效输入
            }
            else {
                payload.length = strlen(input_buf); // timed_get_input_line 确保了不超过 buffer size
                memcpy(payload.data, input_buf, payload.length);
                payload_input_ok = true; // 成功获取非空 payload
            }
        }

        if (!payload_input_ok) {
            printf("输入 ASCII 数据超时！\n");
            return false;
        }
        break;
    }

    case 3: { // 随机生成
        printf("请输入随机字节数 (1-1500):\n");
        DWORD start_time_rand = GetTickCount64();
        DWORD time_limit_rand = INPUT_TIMEOUT_MS;
        long len_val = 0;

        while (GetTickCount64() - start_time_rand < time_limit_rand && !payload_input_ok) {
            DWORD remaining_time = time_limit_rand - (GetTickCount64() - start_time_rand);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[10] = { 0 };
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n输入超时！\n");
                return false;
            }

            char* endptr;
            len_val = strtol(input_buf, &endptr, 10);

            // 验证: 必须是纯数字，且在 1-1500 范围内
            if (endptr != input_buf && *endptr == '\0' && len_val >= 1 && len_val <= 1500) {
                payload.length = static_cast<size_t>(len_val);
                // 生成随机数据 (确保 srand 已在 main 中调用)
                for (size_t i = 0; i < payload.length; ++i) {
                    payload.data[i] = static_cast<u_char>(rand() % 256);
                }
                printf("已生成 %zu 字节随机数据。\n", payload.length);
                payload_input_ok = true; // 成功
            }
            else {
                printf("错误：无效的数字 (必须是 1 到 1500 之间的整数)！请重试。\n");
            }
        }

        if (!payload_input_ok) {
            printf("输入随机长度超时或失败！\n");
            return false;
        }
        break;
    }

    }
    payload.enabled = true;
    printf("Payload 数据设置成功 (长度: %zu 字节)。\n", payload.length);
    return true; // 函数成功返回
}

inline void timed_pause(DWORD seconds, const char* message = nullptr) {
    if (message) {
        printf("\n%s\n", message);
        fflush(stdout);
    }

    if (seconds > 0) {
        // 显示倒计时（可选）
        printf("等待中（剩余时间：");
        for (DWORD i = seconds; i > 0; --i) {
            printf("%lu...", i);
            fflush(stdout); // 每次数字变化都刷新
            Sleep(1000);

            // 增加按键跳过功能
            if (_kbhit()) {
                getchar();
                printf("\n用户手动跳过等待\n");
                break;
            }
        }
    }
}

// 清空输入缓冲区
inline void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// 在所有关键操作后添加fflush
inline void print_pcap_error(const char* prefix, char* errbuf) {
    fprintf(stderr, "%s：%s\n", prefix, errbuf);
    fflush(stderr); // 确保错误信息立即显示
}
