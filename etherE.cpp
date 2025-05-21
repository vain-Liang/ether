/* 使用Npccap兼容WinPcap的驱动进行以太帧发送的程序
 * 编译需要安装 Npcap-SDK 并引入到项目库
 * 自定义MAC地址和以太网类型，并通过指定的网络接口发送以太网帧。
 * 需要在Windows系统上运行，且需安装Npcap驱动。
*/

#define WPCAP
#define HAVE_REMOTE

// #include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
// #include <string.h>
#include <winsock2.h> // 用于htons, WSADATA
#include <windows.h>  // 用于GetTickCount64, WaitForSingleObject, GetStdHandle, Sleep
#include "etherE.h"
// #include <conio.h>

#pragma comment(lib, "ws2_32.lib") // 链接ws2_32库
#pragma comment(lib, "wpcap.lib") // 链接wpcap库

static pcap_if_t* cached_alldevs = NULL;
static DWORD devlist_cache_time = 0;

int main() {
    pcap_if_t* alldevs = NULL;
    pcap_if_t* d = NULL;
    pcap_t* adhandle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    WSADATA wsaData;

    MacPair current_mac;

    // 状态变量
    char selected_interface_name[1024] = { 0 };
    char selected_interface_desc[1024] = { 0 };
    
    bool has_last_macs = false;
    bool reuse_interface = false;
    bool reuse_macs = false;

    // --- 初始化 ---
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup 初始化失败！\n");
        timed_pause(MESSAGE_WAIT_SECONDS); // 退出前等待
        return 1;
    }

    printf("自定义 MAC 地址的原始以太网帧发送程序\n");
    printf("======================================================\n");
    printf("输入/输出操作最长等待时间：%lu 秒\n\n", MESSAGE_WAIT_SECONDS);

    PostSendAction current_action = RESTART_ALL; // 初始操作

    // --- 主程序循环 ---
    while (current_action != EXIT_PROGRAM) {
        // u_char packet_buffer[1514]; // 最大以太网帧大小
        ether_header* eth_header = (ether_header*)packet_buffer;
        u_char* payload_ptr = packet_buffer + sizeof(ether_header);
        int payload_len = 0; // 默认无负载数据
        int frame_len = 0;

        // 每次使用前清空历史数据
        memset(payload_ptr, 0, sizeof(packet_buffer) - sizeof(ether_header));

        // 根据操作重置重用标志
        reuse_interface = (current_action == SEND_AGAIN_SAME_ALL);
        reuse_macs = (current_action == SEND_AGAIN_SAME_ALL || current_action == SEND_AGAIN_SAME_MACS_NEW_INTERFACE);

        // --- 1. 选择网络接口 ---
        if (!reuse_interface || adhandle == NULL) { // 需要选择新接口时
            if (adhandle) { // 关闭之前的接口句柄
                pcap_close(adhandle);
                adhandle = NULL;
            }

            printf("\n--- 选择网络接口 ---\n");

            // 缓存有效期为15秒
            if (!cached_alldevs || (GetTickCount64() - devlist_cache_time > 15000)) {
                if (cached_alldevs) {
                    pcap_freealldevs(cached_alldevs);
                    cached_alldevs = NULL;
                }
                if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &cached_alldevs, errbuf) == -1) {
                    print_pcap_error("查找网络接口设备时出错", errbuf);
                    timed_pause(MESSAGE_WAIT_SECONDS);
                    current_action = EXIT_PROGRAM;
                    continue;
                }
                devlist_cache_time = GetTickCount64();
            }

            if (!cached_alldevs) {
                fprintf(stderr, "无可用网络接口！请检查Npcap安装状态。\n");
                timed_pause(MESSAGE_WAIT_SECONDS);
                current_action = EXIT_PROGRAM;
                continue;
            }

            // 显示接口列表（使用缓存数据）
            printf("可用网络接口列表（缓存更新于%llu秒前）:\n",
                (GetTickCount64() - devlist_cache_time) / 1000);
            int i = 0;
            for (d = cached_alldevs; d != NULL; d = d->next) {
                printf("%d. %s", ++i, d->name);
                if (d->description) printf(" (%s)\n", d->description);
                else printf(" (无描述信息)\n");
            }

            printf("\n================================================\n");
            printf("0. 退出程序\n");

            int inum = -1;
            bool input_ok = false;
            DWORD start_time = GetTickCount64();
            DWORD time_limit = INPUT_TIMEOUT_MS;

            while (GetTickCount64() - start_time < time_limit && !input_ok) {
                DWORD remaining_time = time_limit - (GetTickCount64() - start_time);
                printf("\n请输入接口编号 (1-%d，0退出) [剩余时间：%lu 秒]：", i, remaining_time / 1000);
                char input_buffer[10];

                if (timed_get_input_line(input_buffer, sizeof(input_buffer), remaining_time)) {
                    if (sscanf_s(input_buffer, "%d", &inum) == 1) {
                        if (inum == 0) {
                            printf("正在退出程序...\n");
                            current_action = EXIT_PROGRAM;
                            input_ok = true;
                        }
                        else if (inum >= 1 && inum <= i) {
                            input_ok = true;
                        }
                        else {
                            printf("无效的编号，请重新输入！\n");
                        }
                    }
                    else {
                        printf("输入格式错误，请输入数字！\n");
                    }
                }
                else {
                    current_action = EXIT_PROGRAM;
                    break; // 输入超时退出循环
                }
            }

            if (!input_ok && current_action != EXIT_PROGRAM) {
                printf("\n选择接口时输入超时！\n");
                current_action = EXIT_PROGRAM;
            }

            if (current_action == EXIT_PROGRAM) {
                if (alldevs) pcap_freealldevs(alldevs);
                continue; // 返回主循环处理退出
            }

            // 定位到选中的设备
            d = cached_alldevs;
            for (int i = 0; d != NULL && i < inum - 1; d = d->next, i++);
            if (d == NULL) {
                fprintf(stderr, "无效的设备编号！\n");
                current_action = EXIT_PROGRAM;
                continue;
            }

            // 存储接口信息
            strncpy_s(selected_interface_name, sizeof(selected_interface_name), d->name, _TRUNCATE);
            strncpy_s(selected_interface_desc, sizeof(selected_interface_desc), d->description ? d->description : "N/A", _TRUNCATE);

            // 打开适配器
            adhandle = pcap_open(selected_interface_name, 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1, NULL, errbuf);

            if (adhandle == NULL) {
                fprintf(stderr, "\n无法打开适配器：'%s'\n", selected_interface_name);
                print_pcap_error("Pcap错误", errbuf);
                fprintf(stderr, "请确认以管理员权限运行并正确安装Npcap！\n");
                timed_pause(MESSAGE_WAIT_SECONDS);
                current_action = EXIT_PROGRAM;
                if (alldevs) pcap_freealldevs(alldevs);
                // alldevs = NULL; // 清空设备列表
                continue;
            }
            printf("\n成功打开接口：%s\n", selected_interface_desc);
            // pcap_freealldevs(alldevs);
            alldevs = NULL;

        }
        else {
            printf("\n--- 复用接口：%s ---\n", selected_interface_desc);
        }

        // --- 2. 获取MAC地址和以太网类型 ---
        if (!reuse_macs || !has_last_macs) {
            printf("\n--- 输入发送帧详细信息 ---\n");
            has_last_macs = false; // 重置标志
            
            char dest_mac_str[20];
            char src_mac_str[20];
            

            // 获取目标MAC

            bool input_ok = false;
            DWORD time_limit = INPUT_TIMEOUT_MS;


            printf("请输入目标MAC地址（例如：FF:FF:FF:FF:FF:FF）[剩余时间：%lu 秒]：", time_limit / 1000);
            /*
            if (timed_get_input_line(dest_mac_str, sizeof(dest_mac_str), time_limit)) {
                input_ok = parse_mac_address(dest_mac_str, last_dest_mac);
            }
            */
            if (!timed_get_input_line(dest_mac_str, sizeof(dest_mac_str), INPUT_TIMEOUT_MS) ||
                !parse_mac_address(dest_mac_str, current_mac.dest)) {
                printf("目标MAC输入无效！\n");
                continue;
            }

            /*
            if (!input_ok) {
                printf("\n输入超时或无效！\n");
                current_action = EXIT_PROGRAM;
                continue;
            }
            */

            // 获取源MAC
            input_ok = false;
            printf("请输入源MAC地址（例如：00:11:22:AA:BB:CC）[剩余时间：%lu 秒]：", time_limit / 1000);
            if (!timed_get_input_line(src_mac_str, sizeof(src_mac_str), INPUT_TIMEOUT_MS) ||
                !parse_mac_address(src_mac_str, current_mac.src)) {
                printf("源MAC输入无效！\n");
                continue;
            }

            current_mac.valid = true;
            has_last_macs = true; // 所有输入成功

        }

        PostSendAction result = ethertype_selection_interface(
            adhandle,
            current_mac.dest,
            current_mac.src,
            selected_interface_desc
        );

        // 处理返回结果
        switch (result) {
        case RESTART_ALL:
            current_action = RESTART_ALL;
            current_mac.valid = false; // 重置MAC状态
            break;
        case EXIT_PROGRAM:
            current_action = EXIT_PROGRAM;
            break;
        default:
            current_action = RESTART_ALL;
        }
    }
    // --- 清理资源 ---
    printf("\n正在清理资源并退出...\n");
    if (adhandle) {
        pcap_close(adhandle);
    }
    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
    if (cached_alldevs) {
        pcap_freealldevs(cached_alldevs);
        cached_alldevs = NULL;
    }
    WSACleanup();

    return 0;
}