//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2022, fmad engineering llc 
//
// top level C boot strap libary 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <ctype.h> 
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <zstd.h>
#include <execinfo.h>

#include <immintrin.h>

#include "luajit/lua.h"
#include "luajit/lauxlib.h"
#include "luajit/lualib.h"

#include "src/fTypes.h"

//-------------------------------------------------------------------------------

bool 			g_SignalExit = 0;

double			TSC2Nano 	= 0.0;

static int		s_ArgC 		= 0;				// copy of all the args
static char**	s_ArgV;

//-------------------------------------------------------------------------------

void fmadio_trace(const u8* File, const u8* Func, u32 Line, char* Message, ...)
{
	va_list arglist;
	va_start(arglist, Message);

	char buf[128*1024];
	vsprintf(buf, Message, arglist);

	fprintf(stdout, buf);
}

//-------------------------------------------------------------------------------

static void lsignal (int i, siginfo_t* si, void* context)
{
	fprintf(stderr, "signal received SIG:%i : %p\n", i, context);

	fprintf(stderr, "   si_signo  : %4i %08x\n", si->si_signo, si->si_signo);
	fprintf(stderr, "   si_errno  : %4i %08x\n", si->si_errno, si->si_errno);
	fprintf(stderr, "   si_code   : %4i %08x\n", si->si_code,  si->si_code);
	//fprintf(stderr, "   si_trapno : %i\n", si->si_trapno);

	switch (i)
	{
	case SIGTRAP:
	case SIGSEGV:
	case SIGBUS:
		fprintf(stderr, "    Bus error: 0x%016llx\n", si->si_addr);
		break;

	default:
		fprintf(stderr, "    undef signal\n"); 
		break;
	}
	fflush(stderr);

	signal(i, SIG_DFL); /* if another SIGINT happens before lstop, terminate process (default action) */

	// get execution context
	//mcontext_t* mcontext = &((ucontext_t*)context)->uc_mcontext;
	//fprintf(stderr, "   EPI: %016llx\n", mcontext->gregs[REG_RIP]);

//	fprintf(stderr, "stack trace\n");
//	stack_trace();
//	fprintf(stderr, "stack trace.. done\n");

	// signal related threads to exit
	g_SignalExit = 1;
//	lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

static int lsignal_is(lua_State* L)
{
	lua_pushboolean(L, g_SignalExit);
	return 1;
}

//-------------------------------------------------------------------------------

static void laction (int i)
{
	signal(i, SIG_DFL); /* if another SIGINT happens before lstop, terminate process (default action) */
	trace("signal received (action)\n");

	g_SignalExit = 1;
//	lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

//-------------------------------------------------------------------------------

static int ltrace(lua_State *L) 
{
	FILE* F = stdout; 
	int n = lua_gettop(L);  /* number of arguments */
	int i;
	lua_getglobal(L, "tostring");
	for (i=1; i<=n; i++) 
	{
		char *s;
		size_t len;
		lua_pushvalue(L, -1);  /* function to be called */
		lua_pushvalue(L, i);   /* value to print */
		lua_call(L, 1, 1);
		s = (char*)lua_tolstring(L, -1, &len);  /* get result */
		if (s == NULL)
		{
			return luaL_error(L, LUA_QL("tostring") " must return a string to " LUA_QL("print"));
		}
		/*
		if (i>1)
		{
			fprintf(F,"\t");
		}
		*/
		/*
		if (!s_TraceFileSet)
		{
			fprintf(F, s);
		}
		*/
		// dont allow any message expansion
		fmadio_trace("lua", __FUNCTION__, __LINE__, s);
		lua_pop(L, 1);
	}
	fflush(F);
	return 0;
}

//-------------------------------------------------------------------------------
// dumps the stack trace
void stack_trace (void)
{
	void *array[100];
	char **strings;
	int size, i;
	
	size 	= backtrace (array, 100);
	if (size <= 0) return;

	strings = backtrace_symbols (array, size);
	if (strings != NULL)
	{
		fprintf (stderr, "stack_trace: Obtained %d stack frames.\n", size);
		for (i = 0; i < size; i++)
		{
			//printf ("%s\n", strings[i]);

			u32 p = 0;

			u8 program_name_len = 0;
			u8 program_name[128];

			while (p < strlen(strings[i]))
			{
				u32 c = strings[i][p];
				if (c == '(')
				{
					program_name[program_name_len++] = 0; 
					break;
				}
				program_name[program_name_len++] = c; 
				p++;
			}

			// find address
			while (p < strlen(strings[i]))
			{
				u32 c = strings[i][p];
				p++;

				if (c == '[') break;
			}

			u8 address_len = 0;
			u8 address[128];

			while (p < strlen(strings[i]))
			{
				u32 c = strings[i][p];
				if (c == ']')
				{
					address[address_len++] = 0; 
					break;
				}
				address[address_len++] = c; 
				p++;
			}
			//printf("[%s] [%s]\n", program_name, address);

			// convert address to something bit more meaningful
		    char syscom[256];
		    sprintf(syscom,"addr2line -p -e %s -a %s", program_name, address); 

    		FILE* F = popen(syscom, "r");
			
			u8 Output[1024];
			int len = fread(Output, 1, 1024-1, F);
			Output[len] = 0;
			fclose(F);

			fprintf(stderr, "stack_trace: #%-3i [%-20s] %s", i, program_name, Output);
		}
	}
	free (strings);
}

//-------------------------------------------------------------------------------

static int traceback (lua_State *L) 
{
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */

	lua_getfield(L, LUA_GLOBALSINDEX, "debug");
	if (!lua_istable(L, -1)) {
		printf("no debug info\n");
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		printf("no traceback info\n");
		lua_pop(L, 2);
		return 1;
	}

	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	/*
    const char* msg = lua_tostring(L, 1);
    const char* msg2 = lua_tostring(L, 2);
    printf("dump done %s %p\n", msg, msg2); 
	*/
	return 1;
}

//-------------------------------------------------------------------------------

static int docall (lua_State *L, int narg, int clear)
{
	int status;
	int base = lua_gettop(L) - narg;  	/* function index */
	lua_pushcfunction(L, traceback);  	/* push traceback function */
	lua_insert(L, base);  				/* put it under chunk and args */

	signal(SIGINT, (sighandler_t)lsignal);
	status = lua_pcall(L, narg, (clear ? 0 : LUA_MULTRET), base);
	signal(SIGINT, SIG_DFL);

	lua_remove(L, base);  // remove traceback function 

	// force a complete garbage collection in case of errors 
	if (status != 0) lua_gc(L, LUA_GCCOLLECT, 0);
	return status;
}

//-------------------------------------------------------------------------------

static int report(lua_State *L, int status) 
{
	if (status && !lua_isnil(L, -1))
	{
		const char *msg = lua_tostring(L, -1);
		if (msg == NULL) msg = "(error object is not a string)";

		// both just to be sure
		fprintf(stderr, "%s\n", msg);
		lua_pop(L, 1);
		return -1;
	}
	return status;
}


void __assert_fail ( const char* expr, const char *filename, unsigned int line, const char *assert_func )
{

	fprintf(stderr, "**ERROR** %s:%i (%s) assert fail\n", filename, line, expr);
	stack_trace();
	abort();
}

//-------------------------------------------------------------------------------
// this is special because u64 will be a cdata type
u64 ffi_swap64(u64 a)
{
	return swap64(a);
}
u32 ffi_swap32(u32 a)
{
	return swap32(a);
}
u16 ffi_swap16(u16 a)
{
	return swap16(a);
}


u64 ffi_rdtsc(void)
{
	return rdtsc();
}

u64 ffi_clock_ns(void)
{
	return clock_ns();
}

//-------------------------------------------------------------------------------

// sets cpu affinity 
static int lcpu_affinity(lua_State* L)
{
	// input is u64*
	u32 cpu = lua_tonumber(L, -1);
	if (cpu > 128) cpu = 0;

	cpu_set_t	MainCPUS;
	CPU_ZERO(&MainCPUS);
	CPU_SET(cpu, &MainCPUS);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &MainCPUS);

	printf("set cpu: %i\n", cpu);
	
	return 1;
}

//-------------------------------------------------------------------------------
// return size of a file
static int lfile_size (lua_State* L)
{
	const char* Path = lua_tostring(L, -1);
	if (Path == NULL) return 0;

	struct stat s;;
	if (stat(Path, &s) < 0)
	{
		// invalid path
		return 0;
	}

	lua_pushnumber(L, s.st_size);
	//trace("filesize: %li blocks:%i\n", s.st_size, s.st_blocks);
	return 1;
}

//-------------------------------------------------------------------------------

static int lformatDate(lua_State* L)
{
	u64 *p 			= (u64*)lua_topointer(L, -1); 
	u64 t 			= p[0]; 

	clock_date_t c	= ns2clock(t);

	char Str[1024];
	sprintf(Str, "%04i.%02i.%02i", c.year, c.month, c.day);

	lua_pushstring(L, Str);
	return 1;
}

static int lformatTS(lua_State* L)
{
	u64 t = 0;
	u32 Type = lua_type(L, -1);
	switch (Type)
	{
	case LUA_TCDATA:
	{
		u64 *p 	= (u64*)lua_topointer(L, -1); 
		assert(p != NULL);

		t 		= p[0]; 
	}
	break;

	// NOTE: there is precision loss
	case LUA_TNUMBER:
	{
		double d = lua_tonumber(L, -1);
		t = d;
	}
	break;

	default:
	{
		printf("formatTS type undefined: %i\n", Type);
		assert(false);
	}
	break;
	}

	char* Str = FormatTS(t);
	lua_pushstring(L, Str);
	return 1;
}

//-------------------------------------------------------------------------------

void lua_register_os(lua_State* L, const char* FnName, lua_CFunction Func)
{
	lua_getglobal(L, "os");
	assert(!lua_isnil(L, -1));

	lua_pushcfunction(L, Func);
	lua_setfield(L, -2, FnName); 
}

//-------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	CycleCalibration();

	s_ArgC = argc;
	s_ArgV = argv;

	lua_State *L = lua_open();
	luaL_openlibs(L);

	// parse config options
	lua_newtable(L);
	for (int i=0; i < argc; i++)
	{
		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, 1+i);
	}
	lua_setglobal(L, "ARGV");


	lua_register_os(L, "trace",				ltrace);
	lua_register_os(L, "formatTS",			lformatTS);
	lua_register_os(L, "formatDate",		lformatDate);

	lua_register_os(L, "cpu_affinity",		lcpu_affinity);
	lua_register_os(L, "is_signal",			lsignal_is);

	//struct sigaction handler;
	//memset(&handler, 0, sizeof(handler));
  	//handler.sa_sigaction = lsignal;
    //sigemptyset (&handler.sa_mask);
	//handler.sa_flags = SA_SIGINFO;

/*
	sigaction (SIGINT, 	&handler, NULL);
	sigaction (SIGTERM, &handler, NULL);
	sigaction (SIGKILL, &handler, NULL);
	sigaction (SIGHUP, 	&handler, NULL);
	sigaction (SIGBUS, 	&handler, NULL);
	sigaction (SIGSEGV, &handler, NULL);

	// signal handler 
	fprintf(stderr, "register signal handlers\n");
	signal (SIGINT, 	(sighandler_t)lsignal);
	signal (SIGTERM, 	(sighandler_t)lsignal);
	signal (SIGKILL, 	(sighandler_t)lsignal);
	signal (SIGHUP, 	(sighandler_t)lsignal);
	signal (SIGBUS, 	(sighandler_t)lsignal);
	signal (SIGSEGV, 	(sighandler_t)lsignal);
*/

	// load builtin lua files 
	fprintf(stderr, "Setup\n");
	u64 TS0 = clock_ns();
	{
		luaL_dostring(L, "require('lmain')");
		const char* err = lua_tostring(L, -1);
		if (err != NULL)
		{
			printf("main error: %s\n", err);
			return 0;
		}

		lua_getglobal(L, "lmain");
		assert(lua_isnil(L, -1) == false);

		int status = docall(L, 0, 1);
		report(L, status);

	}
	u64 TS1 = clock_ns();

	fprintf(stderr, "Total Time: %.6f sec (%.3f min)\n", (TS1 - TS0) / 1e9, (TS1 - TS0) / 60e9);
	fflush (stdout);
}
