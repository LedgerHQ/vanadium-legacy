#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "rv_cpu.h"
#include "stream.h"

// Used to set least significant bit to zero.
static const uint32_t ZERO_LSB = ~((uint32_t) 1);

static const uint32_t MOD_32 = 0x1f;

static const uint32_t INST_SIZE = 4;

void rv_cpu_reset(struct rv_cpu *cpu)
{
    memset(cpu, 0, sizeof(struct rv_cpu));
}

enum rv_op rv_cpu_decode(uint32_t inst)
{
    if ((inst & 0b11) != 0b11) {
        // Compressed instructions
        switch (inst & 0b11) {
            case 0b00:
                // Compressed instruction, quadrant 0
                switch ((inst >> 13) & 0b111) {
                    case 0b000: return RV_OP_C_ADDI4SPN;
                    case 0b010: return RV_OP_C_LW;
                    case 0b110: return RV_OP_C_SW;
                    default: return RV_OP_UNKNOWN;
                }
                break;
            case 0b01:
                // Compressed instruction, quadrant 1
                switch ((inst >> 13) & 0b111) {
                    case 0b000: return RV_OP_C_ADDI;
                    case 0b001: return RV_OP_C_JAL;
                    case 0b010: return RV_OP_C_LI;
                    case 0b011:
                        switch ((inst >> 7) & 0b11111) {
                            case 0b00010: return RV_OP_C_ADDI16SP;
                            default: return RV_OP_C_LUI;
                        }
                        break;
                    case 0b100:
                        switch ((inst >> 10) & 0b11) {
                            case 0b00: return RV_OP_C_SRLI;
                            case 0b01: return RV_OP_C_SRAI;
                            case 0b10: return RV_OP_C_ANDI;
                            case 0b11:
                                switch ((inst >> 5) & 0b11) {
                                    case 0b00: return RV_OP_C_SUB;
                                    case 0b01: return RV_OP_C_XOR;
                                    case 0b10: return RV_OP_C_OR;
                                    case 0b11: return RV_OP_C_AND;
                                    default: return RV_OP_UNKNOWN;
                                }
                            default: return RV_OP_UNKNOWN;
                        }
                        break;
                    case 0b101: return RV_OP_C_J;
                    case 0b110: return RV_OP_C_BEQZ;
                    case 0b111: return RV_OP_C_BNEZ;
                    default: return RV_OP_UNKNOWN;
                }
                break;
            case 0b10:
                // Compressed instruction, quadrant 2
                switch ((inst >> 13) & 0b111) {
                    case 0b000:
                        switch ((inst >> 7) & 0b11111) {
                            case 0: return RV_OP_UNKNOWN;
                            default: return RV_OP_C_SLLI;
                        }
                    case 0b010:
                        switch ((inst >> 7) & 0b11111) {
                            case 0: return RV_OP_UNKNOWN;
                            default: return RV_OP_C_LWSP;
                        }
                    case 0b100:
                        switch ((inst >> 12) & 0b1) {
                        case 0b0:
                            switch ((inst >> 2) & 0b11111) {
                                case 0b00000: return RV_OP_C_JR;
                                default: return RV_OP_C_MV;
                            }
                        case 0b1:
                            switch ((inst >> 2) & 0b11111) {
                                case 0b00000:
                                    switch ((inst >> 7) & 0b11111) {
                                        case 0b00000: return RV_OP_C_EBREAK;
                                        default: return RV_OP_C_JALR;
                                    }
                                default: return RV_OP_C_ADD;
                            }
                        }
                    case 0b110: return RV_OP_C_SWSP;
                    default: return RV_OP_UNKNOWN;
                }
                break;
            default: return RV_OP_UNKNOWN;
        }
    }

    // uncompressed instruction
    switch (inst & 0x0000007f) {
        case 0x00000037: return RV_OP_LUI;
        case 0x00000017: return RV_OP_AUIPC;
        case 0x0000006f: return RV_OP_JAL;
        case 0x00000067:
            switch (inst & 0x0000707f) {
                case 0x00000067: return RV_OP_JALR;
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000063:
            switch (inst & 0x0000707f) {
                case 0x00000063: return RV_OP_BEQ;
                case 0x00001063: return RV_OP_BNE;
                case 0x00004063: return RV_OP_BLT;
                case 0x00005063: return RV_OP_BGE;
                case 0x00006063: return RV_OP_BLTU;
                case 0x00007063: return RV_OP_BGEU;
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000003:
            switch (inst & 0x0000707f) {
                case 0x00000003: return RV_OP_LB;
                case 0x00001003: return RV_OP_LH;
                case 0x00002003: return RV_OP_LW;
                case 0x00004003: return RV_OP_LBU;
                case 0x00005003: return RV_OP_LHU;
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000023:
            switch (inst & 0x0000707f) {
                case 0x00000023: return RV_OP_SB;
                case 0x00001023: return RV_OP_SH;
                case 0x00002023: return RV_OP_SW;
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000013:
            switch (inst & 0x0000707f) {
                case 0x00000013: return RV_OP_ADDI;
                case 0x00002013: return RV_OP_SLTI;
                case 0x00003013: return RV_OP_SLTIU;
                case 0x00004013: return RV_OP_XORI;
                case 0x00006013: return RV_OP_ORI;
                case 0x00007013: return RV_OP_ANDI;
                case 0x00001013:
                    switch (inst & 0xfe00707f) {
                        case 0x00001013: return RV_OP_SLLI;
                        default: return RV_OP_UNKNOWN;
                    }
                case 0x00005013:
                    switch (inst & 0xfe00707f) {
                        case 0x00005013: return RV_OP_SRLI;
                        case 0x40005013: return RV_OP_SRAI;
                        default: return RV_OP_UNKNOWN;
                    }
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000033:
            switch (inst & 0xfe00707f) {
                case 0x00000033: return RV_OP_ADD;
                case 0x40000033: return RV_OP_SUB;
                case 0x00001033: return RV_OP_SLL;
                case 0x00002033: return RV_OP_SLT;
                case 0x00003033: return RV_OP_SLTU;
                case 0x00004033: return RV_OP_XOR;
                case 0x00005033: return RV_OP_SRL;
                case 0x40005033: return RV_OP_SRA;
                case 0x00006033: return RV_OP_OR;
                case 0x00007033: return RV_OP_AND;
                case 0x02000033: return RV_OP_MUL;
                case 0x02001033: return RV_OP_MULH;
                case 0x02002033: return RV_OP_MULHSU;
                case 0x02003033: return RV_OP_MULHU;
                case 0x02004033: return RV_OP_DIV;
                case 0x02005033: return RV_OP_DIVU;
                case 0x02006033: return RV_OP_REM;
                case 0x02007033: return RV_OP_REMU;
                default: return RV_OP_UNKNOWN;
            }
        case 0x0000000f:
            switch (inst & 0x0000707f) {
                case 0x0000000f:
                    switch (inst & 0xffffffff) {
                        case 0x8330000f: return RV_OP_FENCE_TSO;
                        case 0x0100000f: return RV_OP_PAUSE;
                        default: return RV_OP_FENCE;
                    }
                default: return RV_OP_UNKNOWN;
            }
        case 0x00000073:
            switch (inst & 0xffffffff) {
                case 0x00000073: return RV_OP_ECALL;
                case 0x00100073: return RV_OP_EBREAK;
                default: return RV_OP_UNKNOWN;
            }
        default: return RV_OP_UNKNOWN;
    }
}

static inline uint32_t imm_i(union rv_inst inst)
{
    return (uint32_t) inst.i.i11_0;
}

static inline uint32_t imm_u(union rv_inst inst)
{
    return (uint32_t) (inst.u.i31_12 << 12);
}

static inline uint32_t imm_s(union rv_inst inst)
{
    return (uint32_t) (inst.s.i11_5 << 5 | inst.s.i4_0);
}


static inline uint32_t imm_b(union rv_inst inst)
{
    return (uint32_t) (inst.b.i12   << 12 |
                  inst.b.i11   << 11 |
                  inst.b.i10_5 <<  5 |
                  inst.b.i4_1  <<  1);
}

static inline uint32_t imm_j(union rv_inst inst)
{
    return (uint32_t) (inst.j.i20    << 20 |
                  inst.j.i19_12 << 12 |
                  inst.j.i11    << 11 |
                  inst.j.i10_1  <<  1);
}

// sign extend a 16 bit value
static inline uint32_t sign_extend_h(uint32_t x) {
  return (int32_t)((int16_t)x);
}

// sign extend an 8 bit value
static inline uint32_t sign_extend_b(uint32_t x) {
  return (int32_t)((int8_t)x);
}

/*
 * Return false if the CPU has stopped (because the app exited for instance, or
 * the instruction isn't recognized, false otherwise.)
 */
bool rv_cpu_execute(struct rv_cpu *cpu, uint32_t instruction)
{
    union rv_inst inst = { .inst = instruction };
    enum rv_op op = rv_cpu_decode(instruction);
    uint32_t pc_inc = INST_SIZE;
    uint32_t pc_set = cpu->pc;
    bool success = true;

    switch (op) {
        case RV_OP_ADD:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] + cpu->regs[inst.rs2];
            break;

        case RV_OP_ADDI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] + imm_i(inst);
            break;

        case RV_OP_SUB:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] - cpu->regs[inst.rs2];
            break;

        case RV_OP_AND:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] & cpu->regs[inst.rs2];
            break;

        case RV_OP_ANDI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] & imm_i(inst);
            break;

        case RV_OP_OR:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] | cpu->regs[inst.rs2];
            break;

        case RV_OP_ORI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] | imm_i(inst);
            break;

        case RV_OP_XOR:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] ^ cpu->regs[inst.rs2];
            break;

        case RV_OP_XORI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] ^ imm_i(inst);
            break;

        case RV_OP_SLL:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] << (cpu->regs[inst.rs2] & MOD_32);
            break;

        case RV_OP_SRL:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] >> (cpu->regs[inst.rs2] & MOD_32);
            break;

        case RV_OP_SLLI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] << (imm_i(inst) & MOD_32);
            break;

        case RV_OP_SRLI:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] >> (imm_i(inst) & MOD_32);
            break;

        case RV_OP_SRA:
            cpu->regs[inst.rd] = (uint32_t) ((int32_t) cpu->regs[inst.rs1] >> (cpu->regs[inst.rs2] & MOD_32));
            break;

        case RV_OP_SRAI:
            cpu->regs[inst.rd] = (uint32_t) ((int32_t) cpu->regs[inst.rs1] >> (imm_i(inst) & MOD_32));
            break;

        case RV_OP_SLT:
            cpu->regs[inst.rd] = (int32_t) cpu->regs[inst.rs1] < (int32_t) cpu->regs[inst.rs2];
            break;

        case RV_OP_SLTI:
            cpu->regs[inst.rd] = (int32_t) cpu->regs[inst.rs1] < (int32_t) imm_i(inst);
            break;

        case RV_OP_SLTU:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] < cpu->regs[inst.rs2];
            break;

        case RV_OP_SLTIU:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] < imm_i(inst);
            break;

        case RV_OP_LUI:
            cpu->regs[inst.rd] = imm_u(inst);
            break;

        case RV_OP_AUIPC:
            cpu->regs[inst.rd] = cpu->pc + imm_u(inst);
            break;

        case RV_OP_JAL:
            pc_inc = imm_j(inst);
            cpu->regs[inst.rd] = cpu->pc + INST_SIZE;
            break;

        case RV_OP_JALR:
            //! Attention, rd and rs1 may be the same register.
            pc_set = (cpu->regs[inst.rs1] + imm_i(inst)) & ZERO_LSB;
            pc_inc = 0;
            cpu->regs[inst.rd] = cpu->pc + INST_SIZE;
            break;

        case RV_OP_BEQ:
            pc_inc = cpu->regs[inst.rs1] == cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_BNE:
            pc_inc = cpu->regs[inst.rs1] != cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_BLT:
            pc_inc = (int32_t) cpu->regs[inst.rs1] < (int32_t) cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_BGE:
            pc_inc = (int32_t) cpu->regs[inst.rs1] >= (int32_t) cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_BLTU:
            pc_inc = cpu->regs[inst.rs1] < cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_BGEU:
            pc_inc = cpu->regs[inst.rs1] >= cpu->regs[inst.rs2] ? imm_b(inst) : INST_SIZE;
            break;

        case RV_OP_LB: {
            uint32_t value;
            if (mem_read(cpu->regs[inst.rs1] + (int32_t) imm_i(inst), 1, &value)) {
                cpu->regs[inst.rd] = sign_extend_b(value);
            } else {
                success = false;
            }
            break;
        }

        case RV_OP_LH: {
            uint32_t value;
            if (mem_read(cpu->regs[inst.rs1] + (int32_t) imm_i(inst), 2, &value)) {
                cpu->regs[inst.rd] = sign_extend_h(value);
            } else {
                success = false;
            }
            break;
        }

        case RV_OP_LW: {
            uint32_t value;
            if (mem_read(cpu->regs[inst.rs1] + (int32_t) imm_i(inst), 4, &value)) {
                cpu->regs[inst.rd] = value;
            } else {
                success = false;
            }
            break;
        }

        case RV_OP_LBU: {
            uint32_t value;
            if (mem_read(cpu->regs[inst.rs1] + (int32_t) imm_i(inst), 1, &value)) {
                cpu->regs[inst.rd] = value;
            } else {
                success = false;
            }
            break;
        }

        case RV_OP_LHU: {
            uint32_t value;
            if (mem_read(cpu->regs[inst.rs1] + (int32_t) imm_i(inst), 2, &value)) {
                cpu->regs[inst.rd] = value;
            } else {
                success = false;
            }
            break;
        }

        case RV_OP_SB:
            if (!mem_write(cpu->regs[inst.rs1] + (int32_t) imm_s(inst), 1, cpu->regs[inst.rs2])) {
                success = false;
            }
            break;

        case RV_OP_SH:
            if (!mem_write(cpu->regs[inst.rs1] + (int32_t) imm_s(inst), 2, cpu->regs[inst.rs2])) {
                success = false;
            }
            break;

        case RV_OP_SW:
            if (!mem_write(cpu->regs[inst.rs1] + (int32_t) imm_s(inst), 4, cpu->regs[inst.rs2])) {
                success = false;
            }
            break;

        case RV_OP_ECALL:
            success = ecall(cpu);
            break;

        case RV_OP_MUL:
            cpu->regs[inst.rd] = cpu->regs[inst.rs1] * cpu->regs[inst.rs2];
            break;

        case RV_OP_MULH:
            cpu->regs[inst.rd] = (uint32_t)(((int64_t)(int32_t)cpu->regs[inst.rs1] * (int32_t)cpu->regs[inst.rs2]) >> 32);
            break;

        case RV_OP_MULHSU:
            cpu->regs[inst.rd] = (uint32_t)(((int64_t)(int32_t)cpu->regs[inst.rs1] * cpu->regs[inst.rs2]) >> 32);
            break;

        case RV_OP_MULHU:
            cpu->regs[inst.rd] = (u64)((u64)cpu->regs[inst.rs1] * (u64)cpu->regs[inst.rs2]) >> 32;
            break;

        case RV_OP_DIV:
            if (cpu->regs[inst.rs2] == 0) {
                cpu->regs[inst.rd] = 0xffffffff;
            } else if (cpu->regs[inst.rs1] == (1U << 31) && cpu->regs[inst.rs2] == 0xffffffff) {
                cpu->regs[inst.rd] = cpu->regs[inst.rs1];
            } else {
                cpu->regs[inst.rd] = (int32_t)cpu->regs[inst.rs1] / (int32_t)cpu->regs[inst.rs2];
            }
            break;

        case RV_OP_DIVU:
            if (cpu->regs[inst.rs2] != 0) {
                cpu->regs[inst.rd] = cpu->regs[inst.rs1] / cpu->regs[inst.rs2];
            } else {
                cpu->regs[inst.rd] = 0xffffffff;
            }
            break;

        case RV_OP_REM:
            if (cpu->regs[inst.rs2] == 0) {
                cpu->regs[inst.rd] = cpu->regs[inst.rs1];
            } else if (cpu->regs[inst.rs1] == (1U << 31) && cpu->regs[inst.rs2] == 0xffffffff) {
                cpu->regs[inst.rd] = 0;
            } else {
                cpu->regs[inst.rd] = (int32_t)cpu->regs[inst.rs1] % (int32_t)cpu->regs[inst.rs2];
            }
            break;

        case RV_OP_REMU:
            if (cpu->regs[inst.rs2] != 0) {
                cpu->regs[inst.rd] = cpu->regs[inst.rs1] % cpu->regs[inst.rs2];
            } else {
                cpu->regs[inst.rd] = cpu->regs[inst.rs1];
            }
            break;

        // start of compressed instructions
        case RV_OP_C_ADDI4SPN: {
            int32_t imm = c_nzuimm(inst.inst);
            if (imm != 0) {
                cpu->regs[rp(inst.c.iw.rdp)] = cpu->regs[2] + imm;
            } else {
                // illegal
                success = false;
            }

            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_ADDI16SP: {
            int32_t imm = sext(get_field1(inst.inst, 12, 9, 9) |
                               get_field1(inst.inst, 6, 4, 4) |
                               get_field1(inst.inst, 5, 6, 6) |
                               get_field1(inst.inst, 3, 7, 8) |
                               get_field1(inst.inst, 2, 5, 5), 10);

            cpu->regs[2] += imm;

            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_LW: {
            // CL format
            uint32_t addr = cpu->regs[rp(inst.c.l.rsp)] + (i32)cl_offset(inst.inst);
            uint32_t value;

            if (mem_read(addr, 4, &value)) {
                cpu->regs[rp(inst.c.l.rdp)] = value;
            } else {
                success = false;
            }
            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_SW: {
            // CS format
            uint32_t addr = cpu->regs[rp(inst.c.s.rs1p)] + (i32)cs_offset(inst.inst);
            uint32_t value = cpu->regs[rp(inst.c.s.rs2p)];
            if (!mem_write(addr, 4, value)) {
                success = false;
            }
            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_ADDI: // also including OP_C_NOP 
            // CI format
            if (inst.c.i.rd != 0) {
                cpu->regs[inst.c.i.rd] += sext(ci_imm(inst.inst), 6);
            }
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_J:
            // CJ format
            pc_inc = sext(cj_offset(inst.inst), 12);
            break;

        case RV_OP_C_JAL:
            // CJ format
            pc_inc = sext(cj_offset(inst.inst), 12);
            cpu->regs[1] = cpu->pc + INST_SIZE/2;
            break;

        case RV_OP_C_LI:
            // CI format
            if (inst.c.i.rd != 0) {
                cpu->regs[inst.c.i.rd] = sext(ci_imm(inst.inst), 6);
            }
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_LUI: {
            // CI format
            uint32_t imm = sext(get_field1(inst.inst, 12, 17, 17) | get_field1(inst.inst, 2, 12, 16), 18);
            if (imm != 0) {
                cpu->regs[inst.c.i.rd] = imm;
            } else {
                // illegal
                success = false;
            }
            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_SLLI:
            // CI format
            cpu->regs[inst.c.i.rd] = cpu->regs[inst.c.i.rd] << (ci_imm(inst.inst) & MOD_32);
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_SRLI:
            // CB format
            cpu->regs[rp(inst.c.b.rs1p)] = cpu->regs[rp(inst.c.b.rs1p)] >> (ci_imm(inst.inst) & MOD_32);
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_SRAI:
            // CB format
            cpu->regs[rp(inst.c.b.rs1p)] = (uint32_t) ((int32_t) cpu->regs[rp(inst.c.b.rs1p)] >> (ci_imm(inst.inst) & MOD_32));
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_ANDI:
            // CB format
            cpu->regs[rp(inst.c.b.rs1p)] &= sext(cb_imm(inst.inst), 6);
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_ADD:
            // CR format
            cpu->regs[inst.c.r.rs1] = cpu->regs[inst.c.r.rs1] + cpu->regs[inst.c.r.rs2];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_SUB:
            // CA format
            cpu->regs[rp(inst.c.a.rs1p)] = cpu->regs[rp(inst.c.a.rs1p)] - cpu->regs[rp(inst.c.a.rs2p)];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_XOR:
            // CA format
            cpu->regs[rp(inst.c.a.rs1p)] = cpu->regs[rp(inst.c.a.rs1p)] ^ cpu->regs[rp(inst.c.a.rs2p)];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_OR:
            // CA format
            cpu->regs[rp(inst.c.a.rs1p)] = cpu->regs[rp(inst.c.a.rs1p)] | cpu->regs[rp(inst.c.a.rs2p)];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_AND:
            // CA format
            cpu->regs[rp(inst.c.a.rs1p)] = cpu->regs[rp(inst.c.a.rs1p)] & cpu->regs[rp(inst.c.a.rs2p)];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_JR:
            // CR format
            if (inst.c.r.rs1 != 0) {
                pc_set = cpu->regs[inst.c.r.rs1];
                pc_inc = 0;
            } else {
                success = false;
                pc_inc = INST_SIZE / 2;
            }
            break;

        case RV_OP_C_JALR:
            // CR format
            if (inst.c.r.rs1 != 0) {
                pc_set = cpu->regs[inst.c.r.rs1];
                pc_inc = 0;
                cpu->regs[1] = cpu->pc + INST_SIZE / 2;
            } else {
                success = false;
                pc_inc = INST_SIZE / 2;
            }
            break;

        case RV_OP_C_BEQZ:
            // CB format
            if (cpu->regs[rp(inst.c.b.rs1p)] == 0) {
                pc_inc = (uint32_t)sext(cb_offset(inst.inst), 9);
            } else {
                pc_inc = INST_SIZE / 2;
            }
            break;

        case RV_OP_C_BNEZ:
            // CB format
            if (cpu->regs[rp(inst.c.b.rs1p)] != 0) {
                pc_inc = (uint32_t)sext(cb_offset(inst.inst), 9);
            } else {
                pc_inc = INST_SIZE / 2;
            }
            break;

        case RV_OP_C_LWSP: {
            // CI format
            uint32_t imm = get_field1(inst.inst, 4, 2, 4)
                         | get_field1(inst.inst, 2, 6, 7)
                         | get_field1(inst.inst, 12, 5, 5);

            uint32_t addr = cpu->regs[2] + imm;
            uint32_t value;
            if (mem_read(addr, 4, &value)) {
                cpu->regs[inst.c.i.rd] = value; // rd from the decoded instruction
            } else {
                success = false;
            }
            pc_inc = INST_SIZE / 2;
            break;
        }

        case RV_OP_C_MV:
            // CR format
            cpu->regs[inst.c.r.rs1] = cpu->regs[inst.c.r.rs2];
            pc_inc = INST_SIZE / 2;
            break;

        case RV_OP_C_SWSP: {
            // CSS format
            uint32_t imm = get_field1(inst.inst, 9, 2, 5) | get_field1(inst.inst, 7, 6, 7);
            uint32_t addr = cpu->regs[2] + imm;
            if (!mem_write(addr, 4, cpu->regs[inst.c.ss.rs2])) {
                success = false;
            }
            pc_inc = INST_SIZE / 2;
            break;
        }

        // end of compressed instructions

        case RV_OP_FENCE:
        case RV_OP_FENCE_TSO:
        case RV_OP_PAUSE:
        case RV_OP_EBREAK:
        case RV_OP_C_EBREAK:
        default:
            fatal("instruction not implemented\n");
            success = false;
            break;
    }

    //! Make sure that no operation can change the x0 register
    cpu->regs[RV_REG_ZERO] = 0;
    cpu->pc = pc_set + pc_inc;

    return success;
}
