#ifndef MY_THREAD_H
#define MY_THREAD_H

#include <windows.h>
#include <process.h>

class Mutex
{
	public:
		Mutex() {
			m_mutex = ::CreateMutex(NULL, FALSE, NULL);
		}
		~Mutex() {
			::CloseHandle(m_mutex);
		}

		void Lock() const {
			DWORD d = WaitForSingleObject(m_mutex, INFINITE);
		}
		void Unlock() const {
			::ReleaseMutex(m_mutex);
		}
	private:
		HANDLE m_mutex;
};

class Guard
{
	public:
		Guard(const Mutex&m): m_lock(m) {
			m_lock.Lock();
		}
		~Guard() {
			m_lock.Unlock();
		}
	private:
		const Mutex& m_lock;
};

class MyThread
{
	public:
		MyThread():m_thread(NULL),m_threadId(0){};
		MyThread(unsigned(__stdcall *func)(void*),void* param) {
			m_thread = (HANDLE)_beginthreadex(NULL,0,func,param,0,&m_threadId);
		}
		~MyThread() {
			if(m_thread) {
				CloseHandle(m_thread);
			}
		}
		void join() {
			if(m_thread) {
				WaitForSingleObject(m_thread,-1);
				CloseHandle(m_thread);
				m_thread=NULL;
			}
		}
		void swap(MyThread& t) {
			std::swap(this->m_thread,t.m_thread);
			std::swap(this->m_threadId,t.m_threadId);
		}
	private:
		HANDLE m_thread;
		unsigned m_threadId;
};

#endif
