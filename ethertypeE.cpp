/* ethertype.cpp
* 选择以太类型和MAC地址组合
* E：Payload数据输入，自定义帧内容
*/
#define NOMINMAX

#include "etherE.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <algorithm>

// 常用以太类型表
// https://en.wikipedia.org/wiki/EtherType
const std::vector<EtherTypeEntry> common_ethertypes = {
    {"IPv4", 0x0800},                   // Internet Protocol v4
    {"ARP", 0x0806},                    // Address Resolution Protocol
    {"RARP", 0x8035},                   // Reverse ARP
    {"IPv6", 0x86DD},                   // Internet Protocol v6
    {"VLAN (802.1Q)", 0x8100},          // VLAN-tagged frame
    {"Q-in-Q (802.1ad)", 0x88A8},       // Stacked VLANs
    {"MPLS Unicast", 0x8847},           // MPLS unicast
    {"MPLS Multicast", 0x8848},         // MPLS multicast
    {"LLDP", 0x88CC},                   // Link Layer Discovery Protocol
    {"PPPoE Discovery", 0x8863},        // PPPoE Discovery Stage
    {"PPPoE Session", 0x8864},          // PPPoE Session Stage
    {"Ethernet Flow Control", 0x8808},  // IEEE 802.3x flow control
    {"Jumbo Frames", 0x8870},           // Experimental Ethernet jumbo
    {"PROFINET", 0x8892},               // PROFINET real-time
    {"HSR", 0x892F},                    // High-availability Seamless Redundancy
    {"EtherCAT", 0x88A4},               // Ethernet for Control Automation
    {"IEEE 1588", 0x88F7},              // Precision Time Protocol
    {"FCoE", 0x8906}                    // Fibre Channel over Ethernet
};

// MAC组合模式枚举
enum MacMode {
    ORIGINAL_BOTH = 1,
    ORIGINAL_DEST_NEW_SRC = 2,
    NEW_DEST_ORIGINAL_SRC = 3,
    NEW_BOTH = 4
};

static void display_ethertype_menu(const PayloadConfig& payload) {
    printf("\n=== 以太帧类型选择 ===\n");
    printf("[当前操作超时时间：%d秒]\n", INPUT_TIMEOUT_MS / 1000);
    printf("当前Payload：%s\n", payload.enabled ? format_payload_status(payload).c_str() : "未设置");
    printf("1. 从预设类型选择\n");
    printf("2. 输入自定义类型\n");
    printf("3. 更改MAC地址组合\n");
    printf("4. 设置Payload数据\n");
    printf("5. 返回主界面\n");
    printf("6. 退出程序\n");
}

// 解析自定义类型输入
static u_short parse_custom_ethertype(const char* input) {
    // 支持多种输入格式：0x0800、0800、800等
    unsigned int value;
    if (sscanf_s(input, "0x%x", &value) == 1 ||
        sscanf_s(input, "%x", &value) == 1) {
        if (value <= 0xFFFF) {
            // 验证是否为有效以太类型
            if (value < 0x0600) {
                printf("警告：类型值%04X通常用于长度字段！\n", value);
            }
            return htons((u_short)value);
        }
    }
	return 0xFFFF; // 无效类型返回0xFFFF
}

// MAC组合选择逻辑
static bool select_mac_combination(u_char* dest_mac, u_char* src_mac,
    const u_char* original_dest,
    const u_char* original_src) {
    printf("\n=== MAC地址组合模式 ===\n");
    printf("1. 使用原有组合\n");
    printf("   -> 目标MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
        "   -> 源MAC:   %02X:%02X:%02X:%02X:%02X:%02X\n",
        original_dest[0], original_dest[1], original_dest[2],
        original_dest[3], original_dest[4], original_dest[5],
        original_src[0], original_src[1], original_src[2],
        original_src[3], original_src[4], original_src[5]);
    printf("2. 原有目标MAC + 更改源MAC\n");
    printf("3. 更改目标MAC + 原有源MAC\n");
    printf("4. 更改目标和源MAC\n");

    char choice_buf[10];
    printf("请选择模式：");
    if (!timed_get_input_line(choice_buf, sizeof(choice_buf), INPUT_TIMEOUT_MS)) {
        return false;
    }

    int choice = atoi(choice_buf);
    switch (choice) {
    case ORIGINAL_BOTH:
        memcpy(dest_mac, original_dest, 6);
        memcpy(src_mac, original_src, 6);
        return true;
    case ORIGINAL_DEST_NEW_SRC: {
        printf("请输入新源MAC地址：");
        char new_src[20];
        if (timed_get_input_line(new_src, sizeof(new_src), INPUT_TIMEOUT_MS) &&
            parse_mac_address(new_src, src_mac)) {
            memcpy(dest_mac, original_dest, 6);
            return true;
        }
        break;
    }
    case NEW_DEST_ORIGINAL_SRC: {
        printf("请输入新目标MAC地址：");
        char new_dest[20];
        if (timed_get_input_line(new_dest, sizeof(new_dest), INPUT_TIMEOUT_MS) &&
            parse_mac_address(new_dest, dest_mac)) {
            memcpy(src_mac, original_src, 6);
            return true;
        }
        break;
    }
    case NEW_BOTH: {
        printf("请输入新目标MAC地址：");
        char new_dest[20];
        if (!timed_get_input_line(new_dest, sizeof(new_dest), INPUT_TIMEOUT_MS) ||
            !parse_mac_address(new_dest, dest_mac)) {
            return false;
        }
        printf("请输入新源MAC地址：");
        char new_src[20];
        if (!timed_get_input_line(new_src, sizeof(new_src), INPUT_TIMEOUT_MS) ||
            !parse_mac_address(new_src, src_mac)) {
            return false;
        }
        return true;
    }
    default:
        printf("无效选择！\n");
    }
    return false;
}

static void send_custom_frame(pcap_t* adhandle, const u_char* dest_mac, const u_char* src_mac, u_short ether_type, const PayloadConfig& payload) {
    ether_header eth_hdr{};
    memcpy(eth_hdr.ether_dhost, dest_mac, 6);
    memcpy(eth_hdr.ether_shost, src_mac, 6);
    eth_hdr.ether_type = htons(ether_type);

    u_char packet[1514];
	int header_len = sizeof(ether_header);

	memcpy(packet, &eth_hdr, header_len);

    // 添加Payload
    if (payload.enabled && payload.length > 0) {
        if (payload.length + header_len > sizeof(packet)) {
            printf("错误：Payload数据长度超出最大值！\n");
            return;
        }
        memcpy(packet + header_len, payload.data, payload.length);
    }

    // 计算总长度（满足最小64字节要求）
    int total_len = header_len + payload.length;
    if (total_len < 64) {
        memset(packet + total_len, 0, 64 - total_len);
        total_len = 64;
    }

    printf("类型详情：\n");
    auto it = std::find_if(common_ethertypes.begin(), common_ethertypes.end(),
        [ether_type](const EtherTypeEntry& e) { return e.value == ether_type; });

    if (it != common_ethertypes.end()) {
        printf("*** 标准类型：%s\n", it->name);
    }
    else {
        u_short host_type = ntohs(ether_type);
        if (host_type < 0x0600) {
            printf("*** 注意：此类型值可能被识别为IEEE 802.3长度字段 ***\n");
        }
        else {
            printf("*** 自定义/未注册类型 ***\n");
        }
    }

    printf("\n准备发送帧：\n"
        "目标MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
        "源MAC:  %02X:%02X:%02X:%02X:%02X:%02X\n"
        "类型:   0x%04X\n",
        dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5],
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
        ntohs(ether_type));

    if (pcap_sendpacket(adhandle, packet, total_len) != 0) {
        print_pcap_error("发送失败", pcap_geterr(adhandle));
    }
    else {
        printf("成功发送 %d 字节帧（含 %d 字节Payload）\n", total_len, payload.length);
    }
    timed_pause(1); // 短暂暂停观察结果
}


PostSendAction ethertype_selection_interface(pcap_t* adhandle, const u_char* original_dest, const u_char* original_src, const char* interface_desc) {

	MacPair working_mac;
	PayloadConfig payload;
    memcpy(working_mac.dest, original_dest, 6);
    memcpy(working_mac.src, original_src, 6);

    printf("\n=== 进入以太帧类型选择界面 ===\n");
    printf("当前网络接口：%s\n", interface_desc);

    while (true) {
        printf("\n当前MAC配置：\n");
        printf("目标：%02X:%02X:%02X:%02X:%02X:%02X\n",
            working_mac.dest[0], working_mac.dest[1], working_mac.dest[2],
            working_mac.dest[3], working_mac.dest[4], working_mac.dest[5]);
        printf("源：  %02X:%02X:%02X:%02X:%02X:%02X\n\n",
            working_mac.src[0], working_mac.src[1], working_mac.src[2],
            working_mac.src[3], working_mac.src[4], working_mac.src[5]);

        display_ethertype_menu(payload);
        printf("请输入选择：");
        char choice_buf[10];
        if (!timed_get_input_line(choice_buf, sizeof(choice_buf), INPUT_TIMEOUT_MS)) {
            printf("输入超时，返回主界面！\n");
            return RESTART_ALL;
        }

        int choice = atoi(choice_buf);
        switch (choice) {
        case 1: {
            const int PAGE_SIZE = 10;
            int total_pages = (common_ethertypes.size() + PAGE_SIZE - 1) / PAGE_SIZE;
            int current_page = 0;

            while (true) {
                printf("\n=== 预设以太类型 (第%d/%d页) ===\n", current_page + 1, total_pages);
                int start = current_page * PAGE_SIZE;
                int end = std::min(start + PAGE_SIZE, (int)(common_ethertypes.size()));

                for (int i = start; i < end; ++i) {
                    printf("%2d. %-24s (0x%04X)\n",
                        i + 1,
                        common_ethertypes[i].name,
                        ntohs(common_ethertypes[i].value));
                }

                printf("\n导航命令：n-下一页 p-上一页 0-返回\n");
                printf("请选择类型序号或命令：");

                char input[10];
                if (!timed_get_input_line(input, sizeof(input), INPUT_TIMEOUT_MS)) break;

                if (strcmp(input, "n") == 0) {
                    current_page = std::min(current_page + 1, total_pages - 1);
                }
                else if (strcmp(input, "p") == 0) {
                    current_page = std::max(current_page - 1, 0);
                }
                else if (isdigit(input[0])) {
                    int selection = atoi(input);
                    if (selection == 0) break;
                    if (selection >= start + 1 && selection <= end) {
                        send_custom_frame(adhandle, working_mac.dest, working_mac.src, common_ethertypes[selection - 1].value, payload);
                    }
                    else {
                        printf("无效的序号！\n");
                    }
                }
            }
            break;
        }
        case 2: { // 自定义类型
            printf("请输入以太类型（十六进制，如0800或0x0800）：");
            char custom_type[10];
            if (timed_get_input_line(custom_type, sizeof(custom_type), INPUT_TIMEOUT_MS)) {
                u_short ether_type = parse_custom_ethertype(custom_type);
                if (ether_type != 0xFFFF) {
                    send_custom_frame(adhandle, working_mac.dest, working_mac.src, ether_type, payload);
                }
                else {
                    printf("错误：无效的以太类型格式！\n");
                }
            }
            break;
        }
        case 3: { // 更改MAC组合
            if (!select_mac_combination(working_mac.dest, working_mac.src, original_dest, original_src)) {
                printf("MAC地址输入错误，保持原有设置！\n");
            }
            else {
                printf("MAC地址已更新！\n");
                MacPair new_mac;
                if (select_mac_combination(new_mac.dest, new_mac.src,
                    original_dest, original_src)) {
                    memcpy(working_mac.dest, new_mac.dest, 6);
                    memcpy(working_mac.src, new_mac.src, 6);
                }
            }
            break;
        }
        case 4: {
            srand(static_cast<unsigned>(time(nullptr)));
            if (input_payload(payload)) {
                break;
			}
        }
        case 5: // 返回主界面
            printf("正在返回主界面...\n");
            return RESTART_ALL;
        case 6: // 退出
            printf("正在退出程序...\n");
            return EXIT_PROGRAM;
        default:
            printf("错误：无效的选择！\n");
        }
    }
}