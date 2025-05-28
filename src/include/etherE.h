/* �������ȫ�ֱ��� */
/* ��̫��֡ͷ���ṹ�嶨�� */
/* ������������� */

#pragma once
#include <pcap.h>
#include <winsock2.h>
#include <conio.h>
#include <string>
#include <sstream>
#include <cctype>

struct ether_header {
	u_char ether_dhost[6];         // Ŀ��MAC��ַ
	u_char ether_shost[6];         // ԴMAC��ַ
	u_short ether_type;            // ��̫������
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
   u_char dest[6] = {0};  // ��ʼ��Ŀ��MAC��ַ  
   u_char src[6] = {0};   // ��ʼ��ԴMAC��ַ  
   bool valid = false;  
};

struct PayloadConfig {
    u_char data[1500]; // ���֧��1500�ֽ�
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

const DWORD INPUT_TIMEOUT_MS = 15000;    // ���������ʱʱ�䣨15�룩
const DWORD MESSAGE_WAIT_SECONDS = 10;   // ��Ϣ�ȴ�ʱ�䣨10�룩
static u_char packet_buffer[1514] = { 0 }; // ��̫��֡�����������1514�ֽڣ�


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
    printf("\n���볬ʱ�����������롣\n");
    return false; // ��ʱ�����
}

// ����MAC��ַ�ַ�����֧��ð�š����ַ����޷ָ�����ʽ��
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

    // �������ַ��ָ�
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

    // �����޷ָ�����12λʮ�����ƣ�
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
    return false; // ���н������Զ�ʧ��
}

inline std::string format_payload_status(const PayloadConfig& payload) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d�ֽ� [%02X %02X...]",
        payload.length,
        payload.data[0],
        payload.data[1]);
    return buf;
}

inline bool input_payload(PayloadConfig& payload) {
    payload = PayloadConfig(); // ���� payload ״̬

    printf("\n=== Payload ���� ===\n");
    printf("֧�ָ�ʽ��\n");
    printf("1. ʮ������ (��: AA BB CC �� AABBCC)\n");
    printf("2. ASCII �ַ��� (��: Hello!)\n");
    printf("3. �������\n");

    int choice_num = 0;
    bool choice_ok = false;
    DWORD start_time_choice = GetTickCount64();
    DWORD time_limit_choice = INPUT_TIMEOUT_MS;

    // --- ѭ����ȡ����֤���뷽ʽ ---
    while (GetTickCount64() - start_time_choice < time_limit_choice && !choice_ok) {
        DWORD remaining_time = time_limit_choice - (GetTickCount64() - start_time_choice);
        if ((long)remaining_time <= 0) break; // ��ʱ���

        printf("��ѡ�����뷽ʽ (1-3) [%lu ms remaining]: ", remaining_time);
        char choice_buf[10] = { 0 };
        if (!timed_get_input_line(choice_buf, sizeof(choice_buf), remaining_time)) {
            printf("\n���볬ʱ��\n");
            return false; // ���볬ʱ������ʧ��
        }

        // ��֤�����Ƿ�Ϊ�������� 1, 2, �� 3
        if (strlen(choice_buf) == 1 && isdigit(choice_buf[0])) {
            choice_num = atoi(choice_buf);
            if (choice_num >= 1 && choice_num <= 3) {
                choice_ok = true; // ������Ч
            }
            else {
                printf("������Ч�����뷽ʽ��ţ������ԡ�\n");
            }
        }
        else {
            printf("���������뵥������ (1-3)�������ԡ�\n");
        }
    }

    if (!choice_ok) {
        printf("ѡ�����뷽ʽ��ʱ��ʧ�ܣ�\n");
        return false; // δ���ڳ�ʱǰѡ����Ч��ʽ
    }

    // --- ����ѡ���� Payload ---
    bool payload_input_ok = false;
    switch (choice_num) {
    case 1: { // ʮ����������
        printf("������ʮ���������� (�ո�ָ�����������, ��� 1500 �ֽ�):\n");
        DWORD start_time_hex = GetTickCount64();
        DWORD time_limit_hex = INPUT_TIMEOUT_MS;

        while (GetTickCount64() - start_time_hex < time_limit_hex && !payload_input_ok) {
            DWORD remaining_time = time_limit_hex - (GetTickCount64() - start_time_hex);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[3001] = { 0 }; // 1500 bytes * 2 chars/byte + spaces/null
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n���볬ʱ��\n");
                return false;
            }

            if (strlen(input_buf) == 0) {
                printf("����δ�����κ����ݣ������ԡ�\n");
                continue; // ������ʾ����
            }

            // ����ʮ����������
            payload.length = 0; // ���ü������Ա�����
            std::string hex_string = input_buf;
            std::string current_byte_str;
            bool parse_error = false;

            for (size_t i = 0; i < hex_string.length() && payload.length < 1500; ) {
                // �����ո�
                if (isspace(hex_string[i])) {
                    i++;
                    continue;
                }
                // ��ȡ 1 �� 2 ��ʮ�������ַ�
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
                    // ��ʮ�������ַ���ո�
                    printf("������λ�� %zu ������Ч�ַ� '%c'���������������С�\n", i, hex_string[i]);
                    parse_error = true;
                    break;
                }


                // ת����ǰ�ֽ�
                try {
                    unsigned long byte_val = std::stoul(current_byte_str, nullptr, 16);
                    if (byte_val > 255) { // Should not happen with 1 or 2 hex digits, but check
                        printf("���󣺽����ֽ� '%s' ʱ�����������������С�\n", current_byte_str.c_str());
                        parse_error = true;
                        break;
                    }
                    payload.data[payload.length++] = static_cast<u_char>(byte_val);
                }
                catch (const std::invalid_argument& ia) {
                    printf("�����޷��� '%s' ����Ϊʮ�����ơ��������������С�\n", current_byte_str.c_str());
                    parse_error = true;
                    break;
                }
                catch (const std::out_of_range& oor) {
                    printf("�����ֽ�ֵ '%s' ������Χ���������������С�\n", current_byte_str.c_str());
                    parse_error = true;
                    break;
                }
            }

            if (parse_error) {
                payload.length = 0; // �����������ó���
                continue; // ��ʾ�û���������
            }

            if (payload.length > 0) {
                payload_input_ok = true; // �ɹ���ȡ�ǿ� payload
                if (payload.length >= 1500) {
                    printf("���棺�Ѵﵽ Payload ��󳤶� (1500 �ֽ�)��\n");
                }
            }
            else if (strlen(input_buf) > 0 && !parse_error) {
                // ����ǿգ��������󳤶�Ϊ 0 (����������ֻ�пո�)
                printf("����δ��������Ч��ʮ���������ݣ������ԡ�\n");
                // ��ѭ������������
            }
           
        }

        if (!payload_input_ok) {
            printf("����ʮ���������ݳ�ʱ��δ�ܳɹ�������\n");
            return false; // δ���ڳ�ʱǰ������Ч hex
        }
        break;
    }

    case 2: { // ASCII ����
        printf("�������ı� (��� 1500 �ַ�):\n");
        DWORD start_time_ascii = GetTickCount64();
        DWORD time_limit_ascii = INPUT_TIMEOUT_MS;

        while (GetTickCount64() - start_time_ascii < time_limit_ascii && !payload_input_ok) {
            DWORD remaining_time = time_limit_ascii - (GetTickCount64() - start_time_ascii);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[1501] = { 0 };
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n���볬ʱ��\n");
                return false;
            }

            if (strlen(input_buf) == 0) {
                printf("��ʾ������Ϊ���ַ�����\n");
                payload.length = 0;
                payload_input_ok = true; // ��Ϊ���ַ�������Ч����
            }
            else {
                payload.length = strlen(input_buf); // timed_get_input_line ȷ���˲����� buffer size
                memcpy(payload.data, input_buf, payload.length);
                payload_input_ok = true; // �ɹ���ȡ�ǿ� payload
            }
        }

        if (!payload_input_ok) {
            printf("���� ASCII ���ݳ�ʱ��\n");
            return false;
        }
        break;
    }

    case 3: { // �������
        printf("����������ֽ��� (1-1500):\n");
        DWORD start_time_rand = GetTickCount64();
        DWORD time_limit_rand = INPUT_TIMEOUT_MS;
        long len_val = 0;

        while (GetTickCount64() - start_time_rand < time_limit_rand && !payload_input_ok) {
            DWORD remaining_time = time_limit_rand - (GetTickCount64() - start_time_rand);
            if ((long)remaining_time <= 0) break;

            printf("[%lu ms remaining]: ", remaining_time);
            char input_buf[10] = { 0 };
            if (!timed_get_input_line(input_buf, sizeof(input_buf), remaining_time)) {
                printf("\n���볬ʱ��\n");
                return false;
            }

            char* endptr;
            len_val = strtol(input_buf, &endptr, 10);

            // ��֤: �����Ǵ����֣����� 1-1500 ��Χ��
            if (endptr != input_buf && *endptr == '\0' && len_val >= 1 && len_val <= 1500) {
                payload.length = static_cast<size_t>(len_val);
                // ����������� (ȷ�� srand ���� main �е���)
                for (size_t i = 0; i < payload.length; ++i) {
                    payload.data[i] = static_cast<u_char>(rand() % 256);
                }
                printf("������ %zu �ֽ�������ݡ�\n", payload.length);
                payload_input_ok = true; // �ɹ�
            }
            else {
                printf("������Ч������ (������ 1 �� 1500 ֮�������)�������ԡ�\n");
            }
        }

        if (!payload_input_ok) {
            printf("����������ȳ�ʱ��ʧ�ܣ�\n");
            return false;
        }
        break;
    }

    }
    payload.enabled = true;
    printf("Payload �������óɹ� (����: %zu �ֽ�)��\n", payload.length);
    return true; // �����ɹ�����
}

inline void timed_pause(DWORD seconds, const char* message = nullptr) {
    if (message) {
        printf("\n%s\n", message);
        fflush(stdout);
    }

    if (seconds > 0) {
        // ��ʾ����ʱ����ѡ��
        printf("�ȴ��У�ʣ��ʱ�䣺");
        for (DWORD i = seconds; i > 0; --i) {
            printf("%lu...", i);
            fflush(stdout); // ÿ�����ֱ仯��ˢ��
            Sleep(1000);

            // ���Ӱ�����������
            if (_kbhit()) {
                getchar();
                printf("\n�û��ֶ������ȴ�\n");
                break;
            }
        }
    }
}

// ������뻺����
inline void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// �����йؼ����������fflush
inline void print_pcap_error(const char* prefix, char* errbuf) {
    fprintf(stderr, "%s��%s\n", prefix, errbuf);
    fflush(stderr); // ȷ��������Ϣ������ʾ
}
