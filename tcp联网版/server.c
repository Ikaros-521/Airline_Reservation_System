#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//#include "getch.h"
#include <conio.h>
#include <WinSock2.h>
#pragma comment(lib,"ws2_32.lib")		//加载ws2_32.dll
 
#define MAX_Flight 50   // 最大航班数
#define MAX_Passenger 20    // 单航班最多乘客数
#define MAX_Order 50    // 最大订票数
 
typedef struct Flight
{
    char fid[20];       //航班号
	char fname[20];	    //航班名称
    char start[10];     //起点
    char end[10];       //终点
    int fnum;	        //票数
}Flight;
 
typedef struct Passenger
{
    char pid[20];	    //身份证
    char pname[10];	    //姓名
    char password[20];	//密码
	char tell[20];	    //电话
}Passenger;
 
typedef struct Order
{
    char pid[20];	//身份证
    char fid[20];	//航班号
	int num;	    //票数
}Order;
 
Flight *FLI;    // 定义全局变量
Passenger *PAS;
Order *ORD;

char search_fid[50][20];    // 符合条件的航班号
int search_fnum[50];        // 符合条件的航班票数
int online = 0;             // 是否登录的变量
char online_pid[20];        // 在线用户的身份证
int search_num = 0;         // 符合条件的航班数

char *get_request_content(char *src, char *content, int max_len); // 解析请求的内容
void init_sys(void);	     // 系统初始化
char* show_flight(void);	 // 显示航班表
void exit_sys(void);	     // 退出系统
char* login(char* pid, char* pw);           // 登录
char* logout(void);          // 用户登出
char* passenger_info(void);  // 查询旅客信息
char* order_ticket(char* fid);	 // 生成查询页面
char* search(char* start, char* end);	         // 查询航班
char* order_list(void);	     // 生成订单表
char* del_order(char* fid);	     // 退票
char* get_str(char* str,size_t len);  // 获取字符串
char get_cmd(char start,char end);	  // 获取cmd命令
 
// 主函数
int main(int argv, char* argc[])
{
    system("chcp 65001");
    printf("编码转换完毕\n");
    // 系统初始化
    init_sys();

	// 初始化
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	//创建套接字
	SOCKET servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	//绑定套接字
	struct sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));		//每个字节用0填充
	sockAddr.sin_family = PF_INET;				//使用ipv4
	sockAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	sockAddr.sin_port = htons(8888);			//端口
	bind(servSock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));

	//进入监听状态
	listen(servSock, 20);

    char cmd[1024] = {0};
    char buf[10240] = {0};

    for(;;)
    {
        // 接收客户端消息
        SOCKADDR clntAddr;
        int nSize = sizeof(SOCKADDR);
        SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);

        memset(cmd, 0, sizeof(cmd));
        memset(buf, 0, sizeof(buf));

        printf("收到客户端命令:");
        recv(clntSock, cmd, 1024, 0);
        printf("%s\n", cmd);
        if(NULL != strstr(cmd, "exit_sys"))
        {
            //关闭套接字
	        closesocket(clntSock);
            break;
        }
        else if(NULL != strstr(cmd, "search"))
        {
            char* start = get_request_content(cmd, "start:", 20);
            char* end = get_request_content(cmd, "end:", 20);

            snprintf(buf, 10240, "%s", search(start, end));
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(0 == strncmp(cmd, "1.订票", 10))
        {
            snprintf(buf, 1024, "订票...\n");
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(0 == strncmp(cmd, "0.返回", 10))
        {
            snprintf(buf, 1024, "返回...\n");
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(NULL != strstr(cmd, "order_ticket"))
        {
            char* fid = get_request_content(cmd, "fid:", 20);
            snprintf(buf, 1024, "%s", order_ticket(fid));
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(NULL != strstr(cmd, "order_list"))
        {
            snprintf(buf, 10240, "%s", order_list());
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(NULL != strstr(cmd, "del_order"))
        {
            char* fid = get_request_content(cmd, "fid:", 20);
            snprintf(buf, 10240, "%s", del_order(fid));
        }
        else if(NULL != strstr(cmd, "passenger_info"))
        {
            snprintf(buf, 10240, "%s", passenger_info());
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(NULL != strstr(cmd, "login"))
        {
            char* pid = get_request_content(cmd, "pid:", 20);
            char* pw = get_request_content(cmd, "pw:", 20);
            snprintf(buf, 10240, "%s", login(pid, pw));
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else if(NULL != strstr(cmd, "logout"))
        {
            snprintf(buf, 10240, "%s", logout());
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        else
        {
            snprintf(buf, 20, "错误命令!");
            send(clntSock, buf, strlen(buf) + sizeof(char), 0);
        }
        //关闭套接字
	    closesocket(clntSock);
    }

	//关闭套接字
	closesocket(servSock);

	//终止dll使用
	WSACleanup();

    exit_sys();	    // 退出系统

	return 0;
}

// 解析请求的内容
char *get_request_content(char *src, char *content, int max_len)
{
	char *result = (char *)malloc((max_len) * sizeof(char));
	memset(result, 0, max_len);
	int i = 0;
	char *temp = NULL;
	temp = strstr(src, content);
	if (temp == NULL)
	{
		return NULL;
	}
	temp += strlen(content);
	while (1)
	{
		if (max_len == i)
			break;
		if (temp[i] != ' ')
		{
			result[i] = temp[i];
			i++;
		}
		else
		{
			break;
		}
	}
	return result;
}
 
// 系统初始化
void init_sys(void)
{
	// 申请堆内存、加载数据
	FLI = calloc(MAX_Flight,sizeof(Flight));
	PAS = calloc(MAX_Passenger,sizeof(Passenger));
	ORD = calloc(MAX_Order,sizeof(Order));
	printf("系统初始化中...\n");
 
    // 以只读方式打开 order.txt,如果文件不存在则打开失败，返回值为空。
	FILE* ofrp = fopen("order.txt","r");
    if(NULL == ofrp)    // 打开失败直接退出
    {
        printf("order.txt 打开失败!\n");
        exit(0);
    }
 
    int i = 0;
	for(i = 0; i < MAX_Order; i++)	//读取文本中的数据到内存，全局变量ORD中
	{	
        int num = 0;
		num = fscanf(ofrp,"%s %s %d\n", ORD[i].pid, ORD[i].fid, &ORD[i].num);
	}
 
	FILE* ffrp = fopen("flight.txt","r");
    if(NULL == ffrp)
    {
        printf("flight.txt 打开失败!\n");
        exit(0);
    }
	for(i = 0; i < MAX_Flight; i++)
	{
		int num = 0;
		num = fscanf(ffrp,"%s %s %s %s %d\n", FLI[i].fid, FLI[i].fname, FLI[i].start, FLI[i].end, &FLI[i].fnum);
	}
 
	FILE* pfrp = fopen("passenger.txt","r");
    if(NULL == pfrp)
    {
        printf("passenger.txt 打开失败!\n");
        exit(0);
    }
	for(i = 0; i < MAX_Passenger; i++)
	{
		int num = 0;
		num = fscanf(pfrp,"%s %s %s %s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
	}

    printf("系统初始化完毕!\n");
}
 
// 显示航班表
char* show_flight(void)
{
    static char buf[10240] = {0};
    memset(buf, 0, sizeof(buf));
    int i = 0;
	for(i = 0; i < MAX_Flight; i++)
	{
		if(strlen(FLI[i].fid) != 0)
		{
			snprintf(buf, 10240, "%sid:%s name:%s start:%s end:%s fnum:%d\n", buf, FLI[i].fid, FLI[i].fname, FLI[i].start, FLI[i].end, 
                FLI[i].fnum);
		}
	}

    return buf;
}
 
// 系统结束
void exit_sys(void)
{
    printf("数据插入中...\n");
	FILE* ofwp = fopen("order.txt","w");
	printf("准备插入 order.txt\n");
	int i= 0;
	for(i = 0; i < MAX_Order; i++)	//数据存储回本地
	{
	    int num = 0;
		if(strlen(ORD[i].pid) != 0)
		{
			num = fprintf(ofwp,"%s %s %d\n", ORD[i].pid, ORD[i].fid, ORD[i].num);
			//printf("insert order.txt success\n");
		}
	}
 
    // 以只写方式打开文件flight.txt，如果文件不存在则创建，如果文件存在则把内容清空。
	FILE* ffwp = fopen("flight.txt","w");
	printf("准备插入 flight.txt\n");
	for(i = 0; i < MAX_Flight; i++)
	{
		int num = 0;
		if(strlen(FLI[i].fid) != 0)
		{
			num = fprintf(ffwp,"%s %s %s %s %d\n", FLI[i].fid, FLI[i].fname, FLI[i].start, FLI[i].end, FLI[i].fnum);
			//printf("insert flight.txt success\n");
		}
	}
 
	FILE* pfwp = fopen("passenger.txt","w");
	printf("准备插入 passenger.txt\n");
	for(i = 0; i < MAX_Passenger; i++)
	{
		int num = 0;
		if(strlen(PAS[i].pid) != 0)
		{
			num = fprintf(pfwp,"%s %s %s %s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
			//printf("insert passenger.txt success\n");
		}
	}
	// 释放内存、保存数据
	free(FLI);
	free(PAS);
	free(ORD);
	printf("程序退出\n");
}
 
// 登录
char* login(char* pid, char* pw)
{
    static char buf[100] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 0)	//如果没有登录
    {
        int i = 0;
        int time = 0;
        // 遍历所有乘客
        for(i = 0; i < MAX_Passenger; i++)
        {
            // 数据长度校验
            if(strlen(pid) == 0 || strlen(pw) == 0)
            {
                printf("pid 或 password 不能为空\n");
                time++;
                break;
            }
            // 成功匹配账号密码
            else if(strcmp(PAS[i].pid, pid) == 0 && strcmp(PAS[i].password, pw) == 0)
            {
                snprintf(buf , 100, "登录成功!\n");
                strncpy(online_pid, pid, 20);
                online = 1;
                return buf;
            }
            else if(i == MAX_Passenger-1)
            {
                snprintf(buf , 100, "pid 或 password 错误\n");
                return buf;
            }
        }
        
    }
    else if(online == 1)
    {
        snprintf(buf , 100, "你还没登录呢\n");
        return buf;
    }
    else
    {
        snprintf(buf , 100, "你已被锁定，禁止使用此系统\n");
        return buf;
    }
 
}
 
// 用户登出
char* logout(void)
{
    static char buf[100] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 1)	//如果已经登录
    {
        online = 0;
        snprintf(buf, 100, "登录成功\n");
    }
    else if(online == -1)
    {
        snprintf(buf, 100, "你已被锁定，禁止使用此系统\n");
    }
    else
    {
        snprintf(buf, 100, "你还没有登录呢\n");
    }
    
    return buf;
}
 
// 查询旅客信息
char* passenger_info(void)
{
    static char buf[100] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 1)	//如果已经登录
    {
        //printf("online_pid:");
        //puts(online_pid);
        int i = 0;
        for(i = 0; i < MAX_Passenger; i++)
        {
            if(strcmp(online_pid, PAS[i].pid) == 0)
            {
                snprintf(buf, 100, "pid:%s, pname:%s, password:%s, tell:%s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
                break;
            }
        }
    }
    else if(online == -1)
    {
        snprintf(buf, 100, "你已被锁定，禁止使用此系统\n");
    }
    else
    {
        snprintf(buf, 100, "你还没有登录呢\n");
    }

    return buf;
}
 
// 订票
char* order_ticket(char* fid)
{
    static char buf[100] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 1) // 如果已经登录
    {
        if(0 == strlen(fid))
        {
            snprintf(buf, 100, "fid 为空\n");
            return buf;
        }
        int i = 0;
        for(i = 0; i < search_num; i++)
        {
            //printf("fid:%s s_fid:%s num:%d\n",fid,search_fid[i],search_fnum[i]);
            if(strcmp(fid,search_fid[i]) == 0 && search_fnum[i] > 0)    //查询到对应航班
            {
                snprintf(buf, 100, "订票成功\n");
                int j = 0;
                for(j = 0; j < MAX_Flight; j++) // 遍历航班表
                {
                    if(strcmp(fid, FLI[j].fid) == 0)
                    {
                        FLI[j].fnum--;	//票数减1
                        break;
                    }
                }

                int k = 0;
                for(k = 0; k < MAX_Order; k++)  // 遍历订票表
                {
                    //printf("ready insert...\n");
                    if(strlen(ORD[k].pid) == 0) // 在空位置插入数据
                    {
                        strcpy(ORD[k].pid, online_pid);  // 插入当前用户身份证
                        strcpy(ORD[k].fid, search_fid[i]);   // 插入当前选择的航班号
                        ORD[k].num = 1;
                        printf("插入订票信息成功\n");
                        break;
                    }
                }
                return buf;
            }
            else if(strcmp(fid,search_fid[i]) == 0 && search_fnum[i] == 0)
            {
                snprintf(buf, 100, "无票\n");
                return buf;
            }
            else if(i == MAX_Flight-1)
            {
                snprintf(buf, 100, "不存在此fid\n");
                return buf;
            }
        }
    }
    else if(online == -1)
    {
        snprintf(buf, 100, "你已被锁定，禁止使用此系统\n");
        return buf;
    }
    else
    {
        snprintf(buf, 100, "请登录!\n");
        return buf;
    }
}
 
// 查询航班
char* search(char* start, char* end)
{
    printf("[函数()] 进入 search(%s, %s)\n", start, end);
    static char buf[10240] = {0};
    memset(buf, 0, sizeof(buf));
	int i = 0;
	search_num = 0;
    // 遍历所有航班
	for(i = 0; i < MAX_Flight; i++)
	{
	    if(strlen(start) == 0 || strlen(end) == 0)
		{
			snprintf(buf, 10240, "start 或 end 不能为空\n");
            printf("%s", buf);
			return buf;
		}
		if(strcmp(FLI[i].start, start) == 0 && strcmp(FLI[i].end, end) == 0)
		{
			snprintf(buf, 10240, "%sfid:%s, 票数:%d\n", buf, FLI[i].fid, FLI[i].fnum);
			strncpy(search_fid[search_num], FLI[i].fid, 20);
			search_fnum[search_num] = FLI[i].fnum;
			//printf("search_fid[%d]:%s, search_fun[%d]:%d\n",search_num,search_fid[search_num],search_num,search_fnum[search_num]);
			++search_num;
		}
		if(0 == search_num && i == MAX_Flight-1)
		{
            snprintf(buf, 10240, "没有航班\n");
            printf("%s", buf);
			return buf;
		}
		if(search_num > 0 && i == MAX_Flight-1)
		{
            printf("%s", buf);
			return buf;
		}
	}

    return buf;
}
 
// 输出订单信息
char* order_list(void)
{
    static char buf[10240] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 1)
    {
        int i = 0;
        for(i = 0; i < MAX_Order; i++)
        {
            if(strcmp(online_pid, ORD[i].pid) == 0)
            {
                //printf("online_pid:%s\n",online_pid);
                snprintf(buf, 10240, "%sfid:%s, pid:%s, ticket:%d\n", buf, ORD[i].fid, ORD[i].pid, ORD[i].num);
            }
        }
    }
    else if(online == -1)
    {
        snprintf(buf, 100, "你已被锁定，禁止使用此系统\n");
    }
    else
    {
        snprintf(buf, 100, "请登录!\n");
    }

    return buf;
}
 
// 删除订单
char* del_order(char* fid)
{
    printf("[函数()] 进入 del_order(%s)\n", fid);
    static char buf[100] = {0};
    memset(buf, 0, sizeof(buf));
    if(online == 1)
    {
        int i = 0;
        // 遍历所有订单
        for(i = 0; i < MAX_Order; i++)
        {
            if(strlen(fid) == 0)  //判空
            {
                snprintf(buf, 100, "del_order 的 fid 不能为空\n");
                return buf;
            }
            if(strcmp(fid, ORD[i].fid) == 0)
            {
                memset(ORD[i].pid, '\0', sizeof(ORD[i].pid));
                int j = 0;
                for(j = 0; j < MAX_Flight; j++)
                {
                    if(strcmp(fid, FLI[j].fid) == 0)
                    {
                        FLI[j].fnum++;  // 返还飞机票
                        break;
                    }
                }
                snprintf(buf, 100, "删除成功\n");
                return buf;
            }
        }
    }
    else if(online == -1)
    {
        snprintf(buf, 100, "你已被锁定，禁止使用此系统\n");
    }
    else
    {
        snprintf(buf, 100, "请登录!\n");
    }

    printf("%s", buf);
    return buf;
}
 
// 清理输入缓冲区
/*void clear_stdin(void)
{
	stdin->_IO_read_ptr = stdin->_IO_read_end;//清理输入缓冲区
}
*/
 
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
