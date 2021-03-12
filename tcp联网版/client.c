#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//#include "getch.h"
#include <conio.h>
#include <WinSock2.h>

#pragma comment(lib,"ws2_32.lib")

void start_sys(void);       // 系统开始运行
char *send_cmd_recv_val(char* cmd); // 发送命令，接收返回
void show_flight(void);	    // 显示航班表
void exit_sys(void);	    // 退出系统
void menu(void);		    // 生成主菜单
void login(void);           // 登录
void logout(void);          // 用户登出
void passenger_info(void);  // 查询旅客信息
void search_start(void);	// 生成查询页面
char* search(void);	        // 查询航班
void order_list(void);	    // 生成订单表
void del_order(void);	    // 退票
char* get_str(char* str,size_t len);  // 获取字符串
char get_cmd(char start,char end);	  // 获取cmd命令

int main(int argv, char* argc[])
{
    system("chcp 65001");
    printf("编码转换完毕\n");

    start_sys();
    exit_sys();

	return 0;
}

// 发送命令，接收返回
char *send_cmd_recv_val(char* cmd)
{
    //初始化
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	//创建套接字
	SOCKET clntSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	//向服务器发送消息
	struct sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));			//每个字节都用0填充
	sockAddr.sin_family = PF_INET;
	sockAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	sockAddr.sin_port = htons(8888);
	connect(clntSock, (SOCKADDR*)& sockAddr, sizeof(SOCKADDR));
	
    static char buf[10240] = {0};

    // buf置0
    memset(buf, 0, sizeof(buf));

    send(clntSock, cmd, strlen(cmd) + sizeof(char), 0);
    recv(clntSock, buf, 10240, 0);
	
	//关闭套接字
	closesocket(clntSock);

	//终止dll
	WSACleanup();

    return buf;
}

// 显示航班表
void show_flight(void)
{
    printf("%s\n", send_cmd_recv_val("show_flight"));
}
 
// 系统开始运行
void start_sys(void)
{
	// 进入系统的业务流程控制
	//printf("系统开始运行...\n");
	//show_flight();
	while(true)
	{
		menu();
		switch(get_cmd('0','6')) // 获取键盘输入
		{
			case '1': search_start(); break;
			case '2': order_list(); break;
			case '3': del_order(); break;
			case '4': passenger_info(); break;
			case '5': login(); break;
			case '6': logout(); break;
			case '0': return;
		}
	}
}
 
// 系统结束
void exit_sys(void)
{
    printf("%s\n", send_cmd_recv_val("exit_sys"));
}
 
// 生成主菜单
void menu(void)
{
    printf("\n");
    printf("*********************************\n");
    printf("|                               |\n");
	printf("|      飞机订票系统             |\n");
	printf("*      1.查询航班               *\n");  //查询航班
	printf("|      2.查询订票信息           |\n");   //查询订票信息
	printf("*      3.退订                   *\n");    //退订
	printf("|      4.查询旅客信息           |\n");   //查询旅客信息
	printf("|      5.用户登录               |\n");  //用户登录
	printf("*      6.用户登出               *\n");    //用户登出
	printf("|      0.退出系统               |\n");   //退出系统
	printf("|                               |\n");
	printf("*********************************\n");
	//printf("\n");
}
 
// 登录
void login(void)
{
    char entry_pid[20]; //临时变量身份证
    char entry_pw[20];  //临时变量密码
    printf("请登录!\n");
    printf("请输入pid:");
    get_str(entry_pid, 20);
    printf("请输入密码:");
    get_str(entry_pw, 20);

    char buf[1024] = {0};

    snprintf(buf, 1024, "login pid:%s pw:%s", entry_pid, entry_pw);
    
    printf("%s\n", send_cmd_recv_val(buf));
}
 
// 用户登出
void logout(void)
{
    printf("%s\n", send_cmd_recv_val("logout"));
}
 
// 查询旅客信息
void passenger_info(void)
{
    printf("%s\n", send_cmd_recv_val("passenger_info"));
}
 
// 开始查询航班
void search_start(void)
{
    char buf[10240] = {0};
    snprintf(buf, 10240, "%s", search());
	if(strncmp(buf, "起始地 或 目的地 不能为空\n", 50) != 0 && strncmp(buf, "没有航班\n", 50) != 0)
	{
		printf("1.订票\n");
		printf("0.返回\n");
		char cmd = get_cmd('0', '1');

        memset(buf, 0, sizeof(buf));

		if(cmd == '0')
		{
            snprintf(buf, 10240, "%s", send_cmd_recv_val("0.返回"));
            printf("%s", buf);
            return;
			//start_sys();
		}
		else
		{
            snprintf(buf, 10240, "%s", send_cmd_recv_val("1.订票"));
		    char fid[20];   // 选择的航班号
            printf("请输入fid:");
            get_str(fid, 20);

            snprintf(buf, 1024, "order_ticket fid:%s", fid);
            
            printf("%s\n", send_cmd_recv_val(buf));
		}
	}
}
 
// 查询航班
char* search(void)
{
    char start[10] = {0};
    char end[10] = {0};
    printf("起始地: \n");
	get_str(start, 10);
	printf("目的地: \n");
	get_str(end, 10);
	
    char buf[1024] = {0};
    static char buf2[10240] = {0};
    memset(buf2, 0, sizeof(buf2));

    snprintf(buf, 1024, "search start:%s end:%s", start, end);
    
    snprintf(buf2, 10240, "%s", send_cmd_recv_val(buf));

    printf("%s", buf2);
    
    return buf2;
}
 
// 输出订单信息
void order_list(void)
{
    printf("%s\n", send_cmd_recv_val("order_list"));
}
 
// 删除订单
void del_order(void)
{
    printf("%s\n", send_cmd_recv_val("order_list"));
    char fid[20];
    printf("请输入要删除的fid:");
    get_str(fid, 20);

    char buf[1024] = {0};
    snprintf(buf, 1024, "del_order fid:%s", fid);
    
    printf("%s\n", send_cmd_recv_val(buf));
}
 
// 读取输入字符串
char* get_str(char* str, size_t len)
{
	if(NULL == str)
	{
		puts("空指针！");
		return NULL;
	}
 
	char *in = fgets(str, len, stdin);
 
	size_t cnt = strlen(str);
	if('\n' == str[cnt-1])
	{
		str[cnt-1] = '\0';
	}
	else
	{
		scanf("%*[^\n]");
		scanf("%*c");
	}
	
	//clear_stdin();
 
	return str;
}
 
// 获取cmd命令
char get_cmd(char start, char end)
{
	//clear_stdin();
 
	printf("请输入命令:");
	while(true)
	{
		char val = getch();
		if(val >= start && val <= end)
		{
			printf("%c\n",val);
			return val;
		}
	}
}