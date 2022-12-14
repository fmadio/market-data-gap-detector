
LUAJIT_LUAJIT 		= ../luajit/src/luajit 
LUAJIT_JIT 			= ../luajit/src/jit/bcsave.lua 
LUAJIT_LIB		 	= ../luajit/src/libluajit.a

LUAJIT 				= ./luajit/luajit 
JIT 				= ./luajit/jit/bcsave.lua
LIBLUAJIT 			= ./luajit/libluajit.a

OBJS =
OBJS += src/main.o

LOBJS =
LOBJS += src/lmain.o
LOBJS += src/lgap.o
LOBJS += src/StackTracePlus.o
LOBJS += src/lcpp.o

# open markets decoders
LOBJS += omi/lOpenMarkets.o

EXTLIBS =

DEF = 
DEF += -g
DEF += -O3
DEF += --std=c99 
DEF += -I.
DEF += -I./luajit/src/

DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -Wno-unused
DEF += -Wno-unused-result

LIBS =
LIBS += ./luajit/src/libluajit.a 

LIBS += -ldl
LIBS += -lm
LIBS += -lpthread
#LIBS += -lstdc++

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
	cd luajit/src/; ./luajit -bg  ../../$<  ../../$@ 

%.a: app/%
	make -C $<

market_gap: $(LIBS) $(OBJS) $(LOBJS) luajit
	ar rcs src/luaobjs.a $(LOBJS) 
	gcc -g $(LDFLAG) -o market_gap $(OBJS) $(EXTLIBS) $(LIBS) -Wl,--whole-archive src/luaobjs.a -Wl,--no-whole-archive -Wl,-E 

./luajit/src/libluajit.a:
	make -C luajit

prepare:
# before running luajit - make sure its up to date
	cp -f $(LUAJIT_LUAJIT) $(LUAJIT)
	cp -f $(LUAJIT_JIT) $(JIT)
	cp -f $(LUAJIT_LIB) $(LIBLUAJIT)

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f src/luaobjs.a 
	rm -f market_gap 
	make -C luajit clean	

