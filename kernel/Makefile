
ifndef FORMAT  
$(error FORMAT variable is not set. Please run 'make FORMAT=raw' or 'make FORMAT=qcow2')  
endif  

# 根据FORMAT变量的值，设置相应的编译选项  
ifeq ($(FORMAT), raw)  
CFLAGS += -DRAW  
else ifeq ($(FORMAT), qcow2)  
CFLAGS += -DQCOW2  
else  
$(error Invalid FORMAT value. Please use 'raw' or 'qcow2'.)  
endif  

APPS = virtio

.PHONY: all
all: $(APPS)

KERN_SOURCES = ${APPS:=_kern.c}
USER_SOURCES = ${APPS:=_user.c}
USER_SOURCES += trace_helpers.c
USER_SOURCES += ../libbpf/src/
USER_SOURCES += ../liburing/src/
USER_SOURCES += ../liburing/src/include
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}
USER_LIBS += trace_helpers.o
USER_LIBS += ../libbpf/src/libbpf.a
USER_LIBS += ../liburing/src/liburing.a

KERNEL_SOURCE ?= /usr/src/$(shell uname -r)
KERNEL_INCLUDES := -I$(KERNEL_SOURCE)/tools/lib/
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/generated/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/generated
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/generated/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/linux/kconfig.h
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include

LIBBPF = -L$(KERNEL_SOURCE)/tools/lib/bpf/

$(APPS): %: %_kern.o %_user.o $(USER_LIBS)
	clang -Wall -O2 -g $@_user.o $(USER_LIBS) $(LIBBPF) -lbpf -lelf -pthread -lz -o $@ -lrt

$(USER_OBJECTS): %.o: %.c
	clang -g -O2  -Wall -I .  -c $<  -o $@

$(KERN_OBJECTS): %.o: %.c
	clang -g -O2 \
		-target bpf \
		$(CFLAGS) \
		-c $< -o $@ \
		-D__TARGET_ARCH_x86 \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-Wno-typedef-redefinition \
		$(KERNEL_INCLUDES) \
		-lrt

format:
	VERSION_CONTROL=none indent -linux *.h *.c

clean:
	rm -rf $(APPS) *.o
