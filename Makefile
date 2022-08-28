
LUAJIT_LUAJIT 		= ../luajit/src/luajit 
LUAJIT_JIT 			= ../luajit/src/jit/bcsave.lua 
LUAJIT_LIB		 	= ../luajit/src/libluajit.a

LUAJIT 				= ./luajit/luajit 
JIT 				= ./luajit/jit/bcsave.lua
LIBLUAJIT 			= ./luajit/libluajit.a

OBJS =
OBJS += src/main.o

LOBJS =
LOBJS += src/lmain.e
LOBJS += src/lMarketData.e
LOBJS += src/StackTracePlus.e
LOBJS += src/lcpp.e

EXTLIBS =

DEF = 
DEF += -g
DEF += -O3
DEF += --std=c99 
DEF += -I.

DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -Wno-unused
DEF += -Wno-unused-result
DEF += -march=core-avx2
DEF += -mavx2

LIBS =
LIBS += ./luajit/libluajit.a 

LIBS += -ldl
LIBS += -lm
LIBS += -lpthread
LIBS += -lstdc++

LDFLAG = 
LDFLAG += -lm
LDFLAG += -lc
#LDFLAG += -lpthread
LDFLAG += -g


# This keeps order to the build and makes it easier to add more later on.
all: market_gap 

%.o: %.c
	gcc $(DEF) -c -o $@ -g $<

%.o: %.lua
	cd luajit; ./luajit -bg  ../$<  ../$@ 

%.e: %.lua
	cd luajit; ./luajit -bg  ../$<  ../$@ 

%.a: app/%
	make -C $<

market_gap: $(LIBS) $(OBJS) $(LOBJS)
	ar rcs src/luaobjs.a $(LOBJS) 
	gcc -g $(LDFLAG) -o market_gap $(OBJS) $(EXTLIBS) $(LIBS) -Wl,--whole-archive src/luaobjs.a -Wl,--no-whole-archive -Wl,-E 


prepare:
# before running luajit - make sure its up to date
	cp -f $(LUAJIT_LUAJIT) $(LUAJIT)
	cp -f $(LUAJIT_JIT) $(JIT)
	cp -f $(LUAJIT_LIB) $(LIBLUAJIT)

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f lua/luaobjs.a 
	rm -f market_gap 

