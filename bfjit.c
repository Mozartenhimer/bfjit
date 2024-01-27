#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define __USE_GNU
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#define NOB_IMPLEMENTATION
#include "nob.h"
#define PAGE_SIZE 4096
#define JIT_MEMORY_START (void*)(0x69420)

typedef enum {
    OP_INC             = '+',
    OP_DEC             = '-',
    OP_LEFT            = '<',
    OP_RIGHT           = '>',
    OP_OUTPUT          = '.',
    OP_INPUT           = ',',
    OP_JUMP_IF_ZERO    = '[',
    OP_JUMP_IF_NONZERO = ']',
} Op_Kind;

typedef struct {
    Op_Kind kind;
    size_t operand;
} Op;

typedef struct {
    Op *items;
    size_t count;
    size_t capacity;
} Ops;

typedef struct {
    Nob_String_View content;
    size_t pos;
} Lexer;

bool is_bf_cmd(char ch)
{
    const char *cmds = "+-<>,.[]";
    return strchr(cmds, ch) != NULL;
}

char lexer_next(Lexer *l)
{
    while (l->pos < l->content.count && !is_bf_cmd(l->content.data[l->pos])) {
        l->pos += 1;
    }
    if (l->pos >= l->content.count) return 0;
    return l->content.data[l->pos++];
}

typedef struct {
    size_t *items;
    size_t count;
    size_t capacity;
} Addrs;

bool interpret(Ops ops)
{
    bool result = true;
    Nob_String_Builder memory = {0};
    nob_da_append(&memory, 0);
    size_t head = 0;
    size_t ip = 0;
    while (ip < ops.count) {
        Op op = ops.items[ip];
        switch (op.kind) {
            case OP_INC: {
                memory.items[head] += op.operand;
                ip += 1;
            } break;

            case OP_DEC: {
                memory.items[head] -= op.operand;
                ip += 1;
            } break;

            case OP_LEFT: {
                if (head < op.operand) {
                    printf("RUNTIME ERROR: Memory underflow");
                    nob_return_defer(false);
                }
                head -= op.operand;
                ip += 1;
            } break;

            case OP_RIGHT: {
                head += op.operand;
                while (head >= memory.count) {
                    nob_da_append(&memory, 0);
                }
                ip += 1;
            } break;

            case OP_INPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    fread(&memory.items[head], 1, 1, stdin);
                }
                ip += 1;
            } break;

            case OP_OUTPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    fwrite(&memory.items[head], 1, 1, stdout);
                }
                ip += 1;
            } break;

            case OP_JUMP_IF_ZERO: {
                if (memory.items[head] == 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            } break;

            case OP_JUMP_IF_NONZERO: {
                if (memory.items[head] != 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            } break;
        }
    }

defer:
    nob_da_free(memory);
    return result;
}

typedef struct {
    void (*run)(void *memory);
    size_t len;
} Code;

void free_code(Code code)
{
    munmap(code.run, code.len);
}

typedef struct {
    size_t operand_byte_addr;
    size_t src_byte_addr;
    size_t dst_op_index;
} Backpatch;

typedef struct {
    Backpatch *items;
    size_t count;
    size_t capacity;
} Backpatches;


void* page_align(void* addr){
	return (void*)(((uint64_t)addr>>12)<<12);
}
typedef struct {
    void* low_page;
    void* mem_start;
    void* high_page;
    int n_pages;
} MemoryManager;

static MemoryManager mm = {0};
// You could get away without guard pages, just by putting the memory in a 
// lonely part of memory, but then you don't get guarantees that you're not 
// addressing some other part of the heap
bool mm_alloc(MemoryManager* mm,int n_pages){
    mm->n_pages = n_pages;
    void* memory = mmap(JIT_MEMORY_START, PAGE_SIZE*(n_pages+2),
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        nob_log(NOB_ERROR, "Could not allocate JIT tape memory: %s", strerror(errno));
        return false;
    }
    
    mm->low_page = memory;
    mm->high_page = memory+2*PAGE_SIZE;
    memory += PAGE_SIZE;
    mm->mem_start = memory;
    if(mprotect(mm->mem_start, PAGE_SIZE*n_pages, PROT_READ | PROT_WRITE) != 0){
        nob_log(NOB_ERROR, "Could not change memory permissions: %s", strerror(errno));
        return false;
    }
    return true;
}
void mm_free(MemoryManager*m){
    if(m->low_page)  munmap(m->low_page, PAGE_SIZE);
    if(m->high_page) munmap(m->high_page, PAGE_SIZE);
    if(m->mem_start) munmap(m->mem_start, m->n_pages*PAGE_SIZE);
    memset(m,0,sizeof(*m));
}
void mm_grow(MemoryManager* mm, int n_pages){
    MemoryManager new = {0};
    assert(n_pages >= mm->n_pages);
    mm_alloc(&new, n_pages);
    memcpy(new.mem_start,mm->mem_start,mm->n_pages*PAGE_SIZE);
    munmap(mm->low_page, (mm->n_pages+2)*PAGE_SIZE);
    memcpy(mm, &new, sizeof(*mm));
}
void segfault_handler(int num,siginfo_t * info , void* vcontext){
	// printf("Handling segmentation fault\n");
    ucontext_t* context = vcontext;
	void* addr = info->si_addr;
    uint64_t rdi = context->uc_mcontext.gregs[REG_RDI];
        
    int64_t offset = rdi - (uint64_t)mm.mem_start;
    if(page_align(addr) == mm.low_page){
        nob_log(NOB_ERROR,"Brainfuck program had a memory underflow.\n");
        abort();
    }
    if(page_align(addr) == mm.high_page){
        size_t new_size = mm.n_pages*2;
        mm_grow(&mm,new_size);        
        nob_log(NOB_INFO,"Expanding brainfuck program memory to 0x%lx bytes.\n",new_size*PAGE_SIZE);
        context->uc_mcontext.gregs[REG_RDI] = (uint64_t)(mm.mem_start+offset);
        return;

    }
    // TODO: It make actually be possible to statically determine the reachability of memory addresses.
    // and therefore know that if it's possible to  "skip over" these gaurd pages. 
    // Or alternatively, you could make the guard pages hundreds of gigabytes, which will be fine because 
    // they'll never be commited.
    nob_log(NOB_ERROR,"Brainfuck program went way out of it's address space with offset %ld",offset);
    abort();
}
bool jit_compile(Ops ops, Code *code)
{
    bool result = true;
    Nob_String_Builder sb = {0};
    Backpatches backpatches = {0};
    Addrs addrs = {0};

    for (size_t i = 0; i < ops.count; ++i) {
        Op op = ops.items[i];
        nob_da_append(&addrs, sb.count);
        switch (op.kind) {
            case OP_INC: {
                assert(op.operand < 256 && "TODO: support bigger operands");
                nob_sb_append_cstr(&sb, "\x80\x07"); // add byte[rdi],
                nob_da_append(&sb, op.operand&0xFF);
            } break;

            case OP_DEC: {
                assert(op.operand < 256 && "TODO: support bigger operands");
                nob_sb_append_cstr(&sb, "\x80\x2f"); // sub byte[rdi],
                nob_da_append(&sb, op.operand&0xFF);
            } break;

            // TODO: range checks for OP_LEFT and OP_RIGHT
            case OP_LEFT: {
                nob_sb_append_cstr(&sb, "\x48\x81\xef"); // sub rdi,
                uint32_t operand = (uint32_t)op.operand;
                nob_da_append_many(&sb, &operand, sizeof(operand));
            } break;

            case OP_RIGHT: {
                nob_sb_append_cstr(&sb, "\x48\x81\xc7"); // add rdi,
                uint32_t operand = (uint32_t)op.operand;
                nob_da_append_many(&sb, &operand, sizeof(operand));
            } break;

            case OP_OUTPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    nob_sb_append_cstr(&sb, "\x57");                            // push rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc0\x01\x00\x00\x00", 7); // mov rax, 1
                    nob_sb_append_cstr(&sb, "\x48\x89\xfe");                    // mov rsi, rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc7\x01\x00\x00\x00", 7); // mov rdi, 1
                    nob_da_append_many(&sb, "\x48\xc7\xc2\x01\x00\x00\x00", 7); // mov rdx, 1
                    nob_sb_append_cstr(&sb, "\x0f\x05");                        // syscall
                    nob_sb_append_cstr(&sb, "\x5f");                            // pop rdi
                }
            } break;

            case OP_INPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    nob_sb_append_cstr(&sb, "\x57");                            // push rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc0\x00\x00\x00\x00", 7); // mov rax, 0
                    nob_sb_append_cstr(&sb, "\x48\x89\xfe");                    // mov rsi, rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc7\x00\x00\x00\x00", 7); // mov rdi, 0
                    nob_da_append_many(&sb, "\x48\xc7\xc2\x01\x00\x00\x00", 7); // mov rdx, 1
                    nob_sb_append_cstr(&sb, "\x0f\x05");                        // syscall
                    nob_sb_append_cstr(&sb, "\x5f");                            // pop rdi
                }
            } break;

            case OP_JUMP_IF_ZERO: {
                nob_sb_append_cstr(&sb, "\x8a\x07");     // mov al, byte [rdi]
                nob_sb_append_cstr(&sb, "\x84\xc0");     // test al, al
                nob_sb_append_cstr(&sb, "\x0f\x84");     // jz
                size_t operand_byte_addr = sb.count;
                nob_da_append_many(&sb, "\x00\x00\x00\x00", 4);
                size_t src_byte_addr = sb.count;

                Backpatch bp = {
                    .operand_byte_addr = operand_byte_addr,
                    .src_byte_addr = src_byte_addr,
                    .dst_op_index = op.operand,
                };

                nob_da_append(&backpatches, bp);
            } break;

            case OP_JUMP_IF_NONZERO: {
                nob_sb_append_cstr(&sb, "\x8a\x07");     // mov al, byte [rdi]
                nob_sb_append_cstr(&sb, "\x84\xc0");     // test al, al
                nob_sb_append_cstr(&sb, "\x0f\x85");     // jnz
                size_t operand_byte_addr = sb.count;
                nob_da_append_many(&sb, "\x00\x00\x00\x00", 4);
                size_t src_byte_addr = sb.count;

                Backpatch bp = {
                    .operand_byte_addr = operand_byte_addr,
                    .src_byte_addr = src_byte_addr,
                    .dst_op_index = op.operand,
                };

                nob_da_append(&backpatches, bp);
            } break;

            default: assert(0 && "Unreachable");
        }
    }
    nob_da_append(&addrs, sb.count);

    for (size_t i = 0; i < backpatches.count; ++i) {
        Backpatch bp = backpatches.items[i];
        int32_t src_addr = bp.src_byte_addr;
        int32_t dst_addr = addrs.items[bp.dst_op_index];
        int32_t operand = dst_addr - src_addr;
        memcpy(&sb.items[bp.operand_byte_addr], &operand, sizeof(operand));
    }

    nob_sb_append_cstr(&sb, "\xC3");

    code->len = sb.count;
    code->run = mmap(NULL, sb.count, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code->run == MAP_FAILED) {
        nob_log(NOB_ERROR, "Could not allocate executable memory: %s", strerror(errno));
        nob_return_defer(false);
    }

    // TODO: switch the permissions to only-exec after finishing copying the code. See mprotect(2).
    memcpy(code->run, sb.items, code->len);

defer:
    if (!result) {
        free_code(*code);
        memset(code, 0, sizeof(*code));
    }
    nob_da_free(sb);
    nob_da_free(backpatches);
    nob_da_free(addrs);
    return result;
}

bool generate_ops(const char *file_path, Ops *ops)
{
    bool result = true;
    Nob_String_Builder sb = {0};
    Addrs stack = {0};

    if (!nob_read_entire_file(file_path, &sb)) {
        nob_return_defer(false);
    }
    Lexer l = {
        .content = {
            .data = sb.items,
            .count = sb.count,
        },
    };
    char c = lexer_next(&l);
    while (c) {
        switch (c) {
            case '.':
            case ',':
            case '<':
            case '>':
            case '-':
            case '+': {
                size_t count = 1;
                char s = lexer_next(&l);
                while (s == c) {
                    count += 1;
                    s = lexer_next(&l);
                }
                Op op = {
                    .kind = c,
                    .operand = count,
                };
                nob_da_append(ops, op);
                c = s;
            } break;

            case '[': {
                size_t addr = ops->count;
                Op op = {
                    .kind = c,
                    .operand = 0,
                };
                nob_da_append(ops, op);
                nob_da_append(&stack, addr);

                c = lexer_next(&l);
            } break;

            case ']': {
                if (stack.count == 0) {
                    // TODO: reports rows and columns
                    printf("%s [%zu]: ERROR: Unbalanced loop\n", file_path, l.pos);
                    nob_return_defer(false);
                }

                size_t addr = stack.items[--stack.count];
                Op op = {
                    .kind = c,
                    .operand = addr + 1,
                };
                nob_da_append(ops, op);
                ops->items[addr].operand = ops->count;

                c = lexer_next(&l);
            } break;

            default: {}
        }
    }

    if (stack.count > 0) {
        // TODO: report the location of opening unbalanced bracket
        printf("%s [%zu]: ERROR: Unbalanced loop\n", file_path, l.pos);
        nob_return_defer(false);
    }

defer:
    if (!result) {
        nob_da_free(*ops);
        memset(ops, 0, sizeof(*ops));
    }
    nob_da_free(sb);
    nob_da_free(stack);
    return result;
}

void usage(const char *program)
{
    nob_log(NOB_ERROR, "Usage: %s [--no-jit] <input.bf>", program);
}

int main(int argc, char **argv)
{
    int result = 0;
    Ops ops = {0};
    Code code = {0};
    // void *memory = NULL;

    const char *program = nob_shift_args(&argc, &argv);

    bool no_jit = false;
    const char *file_path = NULL;

    while (argc > 0) {
        const char *flag = nob_shift_args(&argc, &argv);
        if (strcmp(flag, "--no-jit") == 0) {
            no_jit = true;
        } else {
            if (file_path != NULL) {
                usage(program);
                // TODO(multifile): what if we allowed providing several files and executed them sequencially
                // preserving the state of the machine between them? Maybe complicated by TODO(dead).
                nob_log(NOB_ERROR, "Providing several files is not supported");
                nob_return_defer(1);
            }

            file_path = flag;
        }
    }

    if (file_path == NULL) {
        usage(program);
        nob_log(NOB_ERROR, "No input is provided");
        nob_return_defer(1);
    }

    if (!generate_ops(file_path, &ops)) nob_return_defer(1);

    if (no_jit) {
        nob_log(NOB_INFO, "JIT: off");
        if (!interpret(ops)) nob_return_defer(1);
    } else {
        nob_log(NOB_INFO, "JIT: on");


        if (!jit_compile(ops, &code)) nob_return_defer(1);

        if(! mm_alloc(&mm,1)) nob_return_defer(1);
        // Register segmentation fault handler just before running jit code
        struct sigaction sa = {
            .sa_sigaction = segfault_handler,
            .sa_flags = SA_SIGINFO,
        };
        sigemptyset(&sa.sa_mask);
        if(sigaction(SIGSEGV, &sa,NULL) == -1){
            nob_log(NOB_WARNING,"Failed to register segmentation fault handler. Memory management will not work.");
        }
        code.run(mm.mem_start);
        
        sigaction(SIGSEGV,NULL,NULL);
    }

defer:
    mm_free(&mm);
    nob_da_free(ops);
    free_code(code);
    return result;
}

// TODO: Add more interesting examples.
//   Check https://brainfuck.org/ for inspiration
// TODO(dead): Dead code eliminate first loop which traditionally used as a comment.
//   May not work well if we start sequencially executing several files,
//   because consequent files may not start from the zero state.
//   See TODO(multifile).
// TODO: Optimize pattern [-] to just set the current cell to 0.
//   Probably on the level of IR.
// TODO: Windows port.
//   - [ ] Platform specific mapping of executable memory
//   - [ ] Platform specific stdio from JIT compiled machine code
