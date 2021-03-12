#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//#include "getch.h"
#include <conio.h>

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

char start[10]; //起点
char end[10];   //终点
char search_fid[50][20];    //符合条件的航班号
int search_fnum[50];        //符合条件的航班票数
int online = 0;             //是否登录的变量
char online_pid[20];        //在线用户的身份证
int search_num = 0;         //符合条件的航班数

void init_sys(void);	    // 系统初始化
void show_flight(void);	    // 显示航班表
void start_sys(void);	    // 系统开始运行
void exit_sys(void);	    // 退出系统
void menu(void);		    // 生成主菜单
void login(void);           // 登录
void logout(void);          //用户登出
void passenger_info(void);  //查询旅客信息
bool change_pas_info(void); //修改旅客信息
void search_start(void);	// 生成查询页面
bool search(void);	        // 查询航班
void order_list(void);	    // 生成订单表
void del_order(void);	    // 退票
void clear_stdin(void);	    // 清除输入缓冲区
char* get_str(char* str,size_t len);  // 获取字符串
char get_cmd(char start,char end);	  // 获取cmd命令

// 主函数
int main()
{
	init_sys();     // 系统初始化
	start_sys();    // 系统开始运行
	exit_sys();     // 系统结束
	return 0;
}

// 系统初始化
void init_sys(void)
{
	// 申请堆内存、加载数据
	FLI = calloc(MAX_Flight,sizeof(Flight));
	PAS = calloc(MAX_Passenger,sizeof(Passenger));
	ORD = calloc(MAX_Order,sizeof(Order));
	printf("system_init...\n");

    // 以只读方式打开 order.txt,如果文件不存在则打开失败，返回值为空。
	FILE* ofrp = fopen("order.txt","r");
    if(NULL == ofrp)    // 打开失败直接退出
    {
        printf("order.txt open failed!\n");
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
        printf("flight.txt open failed!\n");
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
        printf("passenger.txt open failed!\n");
        exit(0);
    }
	for(i = 0; i < MAX_Passenger; i++)
	{
		int num = 0;
		num = fscanf(pfrp,"%s %s %s %s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
	}
}

// 显示航班表
void show_flight(void)
{
    int i = 0;
	for(i = 0; i < MAX_Flight; i++)
	{
		if(strlen(FLI[i].fid) != 0)
		{
			printf("id:%s name:%s start:%s end:%s fnum:%d\n", FLI[i].fid, FLI[i].fname, FLI[i].start, FLI[i].end, 
                FLI[i].fnum);
		}
	}
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
		switch(get_cmd('0','7')) // 获取键盘输入
		{
			case '1': search_start(); break;
			case '2': order_list(); break;
			case '3': del_order(); break;
			case '4': passenger_info(); break;
			case '5': change_pas_info(); break;
			case '6': login(); break;
			case '7': logout(); break;
			case '0': return;
		}
	}
}

// 系统结束
void exit_sys(void)
{
    printf("data insert...\n");
	FILE* ofwp = fopen("order.txt","w");
	printf("ready insert order.txt\n");
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
	printf("insert flight.txt\n");
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
	printf("insert passenger.txt\n");
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
	printf("exit...\n");
}

// 生成主菜单
void menu(void)
{
    printf("\n");
    printf("********************************\n");
    printf("|                              |\n");
	printf("|      flight order system     |\n");
	printf("*      1.search_flight         *\n");  //查询航班
	printf("|      2.order_list            |\n");   //查询订票信息
	printf("*      3.del_order             *\n");    //退订
	printf("|      4.passenger_info        |\n");   //查询旅客信息
	printf("*      5.change_pas_info       *\n");  //修改旅客信息
	printf("|      6.login                 |\n");  //用户登录
	printf("*      7.logout                *\n");    //用户登出
	printf("|      0.exit_sys              |\n");   //退出系统
	printf("|                              |\n");
	printf("********************************\n");
	//printf("\n");
}

// 登录
void login(void)
{
    if(online == 0)	//如果没有登录
    {
        int i=0;
        int time = 0;
        while(time < 3)
        {
            char entry_pid[20]; //临时变量身份证
            char entry_pw[20];  //临时变量密码
            printf("please login!\n");
            printf("please entry pid:");
            get_str(entry_pid, 20);
            printf("please entry password:");
            get_str(entry_pw, 20);
            // 遍历所有乘客
            for(i = 0; i < MAX_Passenger; i++)
            {
                // 数据长度校验
                if(strlen(entry_pid) == 0 || strlen(entry_pw) == 0)
                {
                    printf("pid or password can't be empty\n");
                    time++;
                    break;
                }
                // 成功匹配账号密码
                else if(strcmp(PAS[i].pid, entry_pid) == 0 && strcmp(PAS[i].password, entry_pw) == 0)
                {
                    printf("login success!\n");
                    strncpy(online_pid, entry_pid, 20);
                    online = 1;
                    return;
                }
                else if(i == MAX_Passenger-1)
                {
                    printf("pid or password error\n");
                    time++;
                }
            }
        }
        online = -1;
        printf("you have been locked,you can use this system now\n");
    }
    else if(online ==1)
    {
        printf("you have been login\n");
    }
    else
    {
        printf("you have been locked,you can use this system now\n");
    }

}

// 用户登出
void logout(void)
{
    if(online == 1)	//如果已经登录
    {
        online = 0;
        printf("logout success\n");
    }
    else if(online == -1)
    {
        printf("you have been locked,you can use this system now\n");
    }
    else
    {
        printf("you have not login\n");
    }
}

// 查询旅客信息
void passenger_info(void)
{
    if(online == 1)	//如果已经登录
    {
        //printf("online_pid:");
        //puts(online_pid);
        int i = 0;
        for(i = 0; i < MAX_Passenger; i++)
        {
            if(strcmp(online_pid, PAS[i].pid) == 0)
            {
                printf("pid:%s, pname:%s, password:%s, tell:%s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
                break;
            }
        }
    }
    else if(online == -1)
    {
        printf("you have been locked,you can use this system now\n");
    }
    else
    {
        printf("you have not login\n");
    }
}

//修改旅客信息
bool change_pas_info(void)
{
    if(online == 1)	//如果已经登录
    {
        printf("your old info:\n");
        int i = 0;
        for(i = 0; i < MAX_Passenger; i++)
        {
            if(strcmp(online_pid, ORD[i].pid) == 0)
            {
                printf("pid:%s, pname:%s\npassword:%s, tell:%s\n", PAS[i].pid, PAS[i].pname, PAS[i].password, PAS[i].tell);
                break;
            }
        }
        char new_pid[20] = {0};
        char new_pname[10] = {0};
        char new_password[20] = {0};
        char new_tell[20] = {0};
        printf("please entry new pid:");
        get_str(new_pid, 20);
        printf("please entry new pname:");
        get_str(new_pname, 10);
        printf("please entry new password:");
        get_str(new_password, 20);
        printf("please entry new tell:");
        get_str(new_tell, 20);
        strncpy(PAS[i].pid, new_pid, 20);
        strncpy(PAS[i].pname, new_pname, 20);
        strncpy(PAS[i].password, new_password, 20);
        strncpy(PAS[i].tell, new_tell, 20);
        printf("change success\n");
    }
    else if(online == -1)
    {
        printf("you have been locked,you can use this system now\n");
    }
    else
    {
        printf("you have not login\n");
    }
}

// 开始查询航班
void search_start(void)
{
	if(search())
	{
		printf("1.order\n");
		printf("0.back\n");
		char cmd = get_cmd('0', '1');
		if(cmd == '0')
		{
		    return;
			//start_sys();
		}
		else
		{
		    char fid[20];   // 选择的航班号
            if(online == 1) // 如果已经登录
            {
                printf("please entry fid:");
                get_str(fid, 20);
				if(0 == strlen(fid))
				{
					printf("fid is empty\n");
				}
                int i = 0;
                for(i = 0; i < search_num; i++)
                {
                    //printf("fid:%s s_fid:%s num:%d\n",fid,search_fid[i],search_fnum[i]);
                    if(strcmp(fid,search_fid[i]) == 0 && search_fnum[i] > 0)    //查询到对应航班
                    {
                        printf("order success\n");
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
                                printf("insert_to_order success\n");
                                break;
                            }
                        }
                        return;
                    }
                    else if(strcmp(fid,search_fid[i]) == 0 && search_fnum[i] == 0)
                    {
                        printf("no ticket\n");
                        search_start();
                    }
                    else if(i == MAX_Flight-1)
                    {
                        printf("don't have this fid\n");
                        search_start();
                    }
                }
            }
            else if(online == -1)
            {
                printf("you have been locked,you can use this system now\n");
            }
            else
            {
                login();
            }
		}
	}
}

// 查询航班
bool search(void)
{
    printf("start: \n");
	get_str(start,10);
	printf("end: \n");
	get_str(end,10);
	int i = 0;
	search_num = 0;
    // 遍历所有航班
	for(i = 0; i < MAX_Flight; i++)
	{
	    if(strlen(start) == 0 || strlen(end) == 0)
		{
			printf("start or end can't be empty\n");
			return false;
		}
		if(strcmp(FLI[i].start, start) == 0 && strcmp(FLI[i].end, end) == 0)
		{
			printf("fid:%s, ticket_num:%d\n", FLI[i].fid, FLI[i].fnum);
			strncpy(search_fid[search_num], FLI[i].fid, 20);
			search_fnum[search_num] = FLI[i].fnum;
			//printf("search_fid[%d]:%s, search_fun[%d]:%d\n",search_num,search_fid[search_num],search_num,search_fnum[search_num]);
			++search_num;
		}
		if(0 == search_num && i == MAX_Flight-1)
		{
			printf("no flight\n");
			return false;
		}
		if(search_num > 0 && i == MAX_Flight-1)
		{
			//show_flight();
			return true;
		}
	}
}

// 输出订单信息
void order_list(void)
{
    if(online == 1)
    {
        int i = 0;
        for(i = 0; i < MAX_Order; i++)
        {
            if(strcmp(online_pid, ORD[i].pid) == 0)
            {
                //printf("online_pid:%s\n",online_pid);
                printf("fid:%s, pid:%s, ticket:%d\n", ORD[i].fid, ORD[i].pid, ORD[i].num);
            }
        }
    }
    else if(online == -1)
    {
        printf("you have been locked,you can use this system now\n");
    }
    else
    {
        login();
    }
}

// 删除订单
void del_order(void)
{
    if(online == 1)
    {
        char fid[20];
        printf("order_list:\n");
        order_list();
        printf("please entry del_order fid:");
        get_str(fid, 20);
        int i = 0;
        // 遍历所有订单
        for(i = 0; i < MAX_Order; i++)
        {
            if(strlen(fid) == 0)  //判空
            {
                printf("del_order fid can't be empty\n");
                return;
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
                printf("delete success\n");
                return;
            }
        }
    }
    else if(online == -1)
    {
        printf("you have been locked,you can use this system now\n");
    }
    else
    {
        login();
    }

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
		puts("empty ptr！");
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

	printf("please entry cmd:");
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
