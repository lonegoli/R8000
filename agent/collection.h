#ifndef _COLLECTION_H_
#define _COLLECTION_H_

typedef struct CPU_OCCUPY_t         //����һ��cpu occupy�Ľṹ��
{
	char name[20];      //����һ��char���͵�������name��20��Ԫ��
	unsigned int user; //����һ���޷��ŵ�int���͵�user
	unsigned int nice; //����һ���޷��ŵ�int���͵�nice
	unsigned int system;//����һ���޷��ŵ�int���͵�system
	unsigned int idle; //����һ���޷��ŵ�int���͵�idle
}CPU_OCCUPY;

typedef struct MEM_OCCUPY_t         //����һ��mem occupy�Ľṹ��
{
	char name[20];      //����һ��char���͵�������name��20��Ԫ��
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
