//
// Created by root on 12/6/22.
//

#include "util.hh"
#include <execinfo.h>
#include <iostream>
#include <sstream>
#include <atomic>
#include <sys/time.h>

namespace hammer {
    pid_t GetThreadId() {
        return syscall(SYS_gettid);
        //return std::this_thread::get_id();
    }

    void setThreadName(const std::string &name) {
    }

    void Backtrace(std::vector<std::string> &bt, int size, int skip) {
        void** array = (void**)malloc(sizeof(void*) * size);
        size_t s = ::backtrace(array, size);
        char** strings = backtrace_symbols(array, size);
        if (strings == NULL) {
            free(array);
            return;
        }

        for (size_t i = skip; i < s; i++) {
            bt.push_back(strings[i]);
        }

        free(array);
        free(strings);
    }

    std::string BacktraceToString(int size, int skip, const std::string& prefix) {
        std::vector<std::string> bt;
        Backtrace(bt, size, skip);
        std::stringstream ss;
        for (size_t i = 0; i < bt.size(); i++) {
            ss << prefix << bt[i] << std::endl;
        }
        return ss.str();
    }

	static int _daylight_active;
	static long _current_timezone;
	int get_daylight_active() {
    	return _daylight_active;
	}

	static int is_leap_year(time_t year) {
    	if (year % 4)
    	    return 0; /* A year not divisible by 4 is not leap. */
    	else if (year % 100)
    	    return 1; /* If div by 4 and not 100 is surely leap. */
    	else if (year % 400)
    	    return 0; /* If div by 100 *and* not by 400 is not leap. */
    	else
    	    return 1; /* If div by 100 and 400 is leap. */
	}

	void no_locks_localtime(struct tm *tmp, time_t t) {
	    const time_t secs_min = 60;
	    const time_t secs_hour = 3600;
	    const time_t secs_day = 3600 * 24;
	
	    t -= _current_timezone; /* Adjust for timezone. */
	    t += 3600 * get_daylight_active(); /* Adjust for daylight time. */
	    time_t days = t / secs_day; /* Days passed since epoch. */
	    time_t seconds = t % secs_day; /* Remaining seconds. */
	
	    tmp->tm_isdst = get_daylight_active();
	    tmp->tm_hour = seconds / secs_hour;
	    tmp->tm_min = (seconds % secs_hour) / secs_min;
	    tmp->tm_sec = (seconds % secs_hour) % secs_min;
	#ifndef _WIN32
	    tmp->tm_gmtoff = -_current_timezone;
	#endif
	    /* 1/1/1970 was a Thursday, that is, day 4 from the POV of the tm structure
	     * where sunday = 0, so to calculate the day of the week we have to add 4
	     * and take the modulo by 7. */
	    tmp->tm_wday = (days + 4) % 7;
	
	    /* Calculate the current year. */
	    tmp->tm_year = 1970;
	    while (1) {
	        /* Leap years have one day more. */
	        time_t days_this_year = 365 + is_leap_year(tmp->tm_year);
	        if (days_this_year > days)
	            break;
	        days -= days_this_year;
	        tmp->tm_year++;
	    }
	    tmp->tm_yday = days; /* Number of day of the current year. */
	
	    /* We need to calculate in which month and day of the month we are. To do
	     * so we need to skip days according to how many days there are in each
	     * month, and adjust for the leap year that has one more day in February. */
	    int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	    mdays[1] += is_leap_year(tmp->tm_year);
	
	    tmp->tm_mon = 0;
	    while (days >= mdays[tmp->tm_mon]) {
	        days -= mdays[tmp->tm_mon];
	        tmp->tm_mon++;
	    }
	
	    tmp->tm_mday = days + 1; /* Add 1 since our 'days' is zero-based. */
	    tmp->tm_year -= 1900; /* Surprisingly tm_year is year-1900. */
	}
	
	void local_time_init() {
	    /* Obtain timezone and daylight info. */
	    tzset(); /* Now 'timezome' global is populated. */
	#if defined(__linux__) || defined(__sun)
	    _current_timezone  = timezone;
	#elif defined(_WIN32)
	    time_t time_utc;
	    struct tm tm_local;
	
	    // Get the UTC time
	    time(&time_utc);
	
	    // Get the local time
	    // Use localtime_r for threads safe for linux
	    //localtime_r(&time_utc, &tm_local);
	    localtime_s(&tm_local, &time_utc);
	
	    time_t time_local;
	    struct tm tm_gmt;
	
	    // Change tm to time_t
	    time_local = mktime(&tm_local);
	
	    // Change it to GMT tm
	    //gmtime_r(&time_utc, &tm_gmt);//linux
	    gmtime_s(&tm_gmt, &time_utc);
	
	    int time_zone = tm_local.tm_hour - tm_gmt.tm_hour;
	    if (time_zone < -12) {
	        time_zone += 24;
	    }
	    else if (time_zone > 12) {
	        time_zone -= 24;
	    }
	
	    _current_timezone = time_zone;
	#else
	    struct timeval tv;
	    struct timezone tz;
	    gettimeofday(&tv, &tz);
	    _current_timezone = tz.tz_minuteswest * 60L;
	#endif
	    time_t t = time(NULL);
	    struct tm *aux = localtime(&t);
	    _daylight_active = aux->tm_isdst;
	} 

	struct tm getLocalTime(time_t sec) {
	    struct tm tm;
	#ifdef _WIN32
	    localtime_s(&tm, &sec);
	#else
	    no_locks_localtime(&tm, sec);
	#endif //_WIN32
	    return tm;
	}
	
	static long s_gmtoff = 0;
	static OnceToken s_token([](){
		local_time_init();
	    s_gmtoff = getLocalTime(time(nullptr)).tm_gmtoff;
	});

	static inline uint64_t getCurrentMicrosecondOrigin() {
		struct timeval tv;
		gettimeofday(&tv, nullptr);
		return tv.tv_sec * 1000000LL + tv.tv_usec;
	}

	static std::atomic<uint64_t>	s_current_mic_sec(0);
	static std::atomic<uint64_t>	s_current_mil_sec(0);
	static std::atomic<uint64_t>	s_current_mic_sec_system(getCurrentMicrosecondOrigin());
	static std::atomic<uint64_t>	s_current_mil_sec_system(getCurrentMicrosecondOrigin()/1000);

	static inline bool initMilSecondThread() {
		static std::thread s_thread([]() {
			setThreadName("timestamp thread");
			uint64_t last = getCurrentMicrosecondOrigin();
			uint64_t now;
			uint64_t mic_sec = 0;
			while (1) {
				now = getCurrentMicrosecondOrigin();
				s_current_mic_sec_system.store(now, std::memory_order_release);
				s_current_mil_sec_system.store(now/1000, std::memory_order_release);
				int64_t expired = now - last;
				last = now;
				if (expired > 0 && expired < 1000 * 1000) {
					mic_sec += expired;
					s_current_mic_sec.store(mic_sec, std::memory_order_release);
					s_current_mil_sec.store(mic_sec/1000, std::memory_order_release);
				} else if (expired != 0) {
					//
				}
				usleep(500);
			}
		});
		static OnceToken s_token([](){
			s_thread.detach();
		});
		return true;
	}

	uint64_t getCurrentMillSecond(bool system_time) {
		initMilSecondThread();
		if (system_time) {
			return s_current_mil_sec_system.load(std::memory_order_acquire);
		}
		return s_current_mil_sec.load(std::memory_order_acquire);
	}

	uint64_t getCurrentMicroSecond(bool system_time) {
		initMilSecondThread();
		if (system_time) {
			return s_current_mic_sec_system.load(std::memory_order_acquire);
		}
		return s_current_mic_sec.load(std::memory_order_acquire);
	}

}
