#ifndef _COLLECTION_H_
#define _COLLECTION_H_

typedef struct CPU_OCCUPY_t         //定义一个cpu occupy的结构体
{
	char name[20];      //定义一个char类型的数组名name有20个元素
	unsigned int user; //定义一个无符号的int类型的user
	unsigned int nice; //定义一个无符号的int类型的nice
	unsigned int system;//定义一个无符号的int类型的system
	unsigned int idle; //定义一个无符号的int类型的idle
}CPU_OCCUPY;

typedef struct MEM_OCCUPY_t         //定义一个mem occupy的结构体
{
	char name[20];      //定义一个char类型的数组名name有20个元素
	unsigned long total; 
	char name2[20];
	unsigned long free;                       
}MEM_OCCUPY;

typedef struct NETWORK_FLOW_t
{
	/*
	unsigned long long rx_bytes;
	unsigned long long tx_bytes;
	unsigned long long rx_packets;
	unsigned long long tx_packets;
	*/
	char rx_bytes[32];
	char tx_bytes[32];
	char rx_packets[32];
	char tx_packets[32];
	char assoc_clients[32];

}NETWORK_FLOW;


void thread_monitor_collection(void *arg);

#endif/*_COLLECTION_H_*/
