/* Capstone Disassembler Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */
 

#ifndef _COMMON_H_
#define _COMMON_H_

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct platform
{
  cs_arch arch;
  cs_mode mode;
  unsigned char *code;
  size_t size;
  char *comment;
  bool detailed;
};

static csh handle;

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
  unsigned char *c;

  printf("%s", comment);

  for (c = str; c < str + len; c++)
  {
    printf("0x%02X ", *c & 0xff);
  }

  printf("\n");
}

static void print_string_hex_short(unsigned char *str, size_t len)
{
  unsigned char *c;

  for (c = str; c < str + len; c++)
  {
    printf("%02X", *c & 0xff);
  }
}

const char s_insn_ids[][16] =
{
 "M680X_INS_INVLD", "M680X_INS_ABA", "M680X_INS_ABX", "M680X_INS_ABY",
 "M680X_INS_ADC", "M680X_INS_ADCA", "M680X_INS_ADCB", "M680X_INS_ADCD",
 "M680X_INS_ADCR", "M680X_INS_ADD", "M680X_INS_ADDA", "M680X_INS_ADDB",
 "M680X_INS_ADDD", "M680X_INS_ADDE", "M680X_INS_ADDF", "M680X_INS_ADDR",
 "M680X_INS_ADDW", "M680X_INS_AIM", "M680X_INS_AIS", "M680X_INS_AIX",
 "M680X_INS_AND", "M680X_INS_ANDA", "M680X_INS_ANDB", "M680X_INS_ANDCC",
 "M680X_INS_ANDD", "M680X_INS_ANDR", "M680X_INS_ASL", "M680X_INS_ASLA",
 "M680X_INS_ASLB", "M680X_INS_ASLD", "M680X_INS_ASR", "M680X_INS_ASRA",
 "M680X_INS_ASRB", "M680X_INS_ASRD", "M680X_INS_ASRX", "M680X_INS_BAND",
 "M680X_INS_BCC", "M680X_INS_BCLR", "M680X_INS_BCS", "M680X_INS_BEOR",
 "M680X_INS_BEQ", "M680X_INS_BGE", "M680X_INS_BGND", "M680X_INS_BGT",
 "M680X_INS_BHCC",
 "M680X_INS_BHCS", "M680X_INS_BHI", "M680X_INS_BIAND", "M680X_INS_BIEOR",
 "M680X_INS_BIH", "M680X_INS_BIL", "M680X_INS_BIOR", "M680X_INS_BIT",
 "M680X_INS_BITA", "M680X_INS_BITB", "M680X_INS_BITD", "M680X_INS_BITMD",
 "M680X_INS_BLE", "M680X_INS_BLS", "M680X_INS_BLT", "M680X_INS_BMC",
 "M680X_INS_BMI", "M680X_INS_BMS", "M680X_INS_BNE", "M680X_INS_BOR",
 "M680X_INS_BPL", "M680X_INS_BRCLR", "M680X_INS_BRSET", "M680X_INS_BRA",
 "M680X_INS_BRN", "M680X_INS_BSET", "M680X_INS_BSR", "M680X_INS_BVC",
 "M680X_INS_BVS", "M680X_INS_CALL", "M680X_INS_CBA", "M680X_INS_CBEQ",
 "M680X_INS_CBEQA",
 "M680X_INS_CBEQX", "M680X_INS_CLC", "M680X_INS_CLI", "M680X_INS_CLR",
 "M680X_INS_CLRA", "M680X_INS_CLRB", "M680X_INS_CLRD", "M680X_INS_CLRE",
 "M680X_INS_CLRF", "M680X_INS_CLRH", "M680X_INS_CLRW", "M680X_INS_CLRX",
 "M680X_INS_CLV", "M680X_INS_CMP", "M680X_INS_CMPA", "M680X_INS_CMPB",
 "M680X_INS_CMPD", "M680X_INS_CMPE", "M680X_INS_CMPF", "M680X_INS_CMPR",
 "M680X_INS_CMPS", "M680X_INS_CMPU", "M680X_INS_CMPW", "M680X_INS_CMPX",
 "M680X_INS_CMPY", "M680X_INS_COM", "M680X_INS_COMA", "M680X_INS_COMB",
 "M680X_INS_COMD", "M680X_INS_COME", "M680X_INS_COMF", "M680X_INS_COMW",
 "M680X_INS_COMX", "M680X_INS_CPD", "M680X_INS_CPHX", "M680X_INS_CPS",
 "M680X_INS_CPX",
 "M680X_INS_CPY", "M680X_INS_CWAI", "M680X_INS_DAA", "M680X_INS_DBEQ",
 "M680X_INS_DBNE", "M680X_INS_DBNZ",
 "M680X_INS_DBNZA", "M680X_INS_DBNZX", "M680X_INS_DEC", "M680X_INS_DECA",
 "M680X_INS_DECB", "M680X_INS_DECD", "M680X_INS_DECE", "M680X_INS_DECF",
 "M680X_INS_DECW", "M680X_INS_DECX", "M680X_INS_DES", "M680X_INS_DEX",
 "M680X_INS_DEY", "M680X_INS_DIV", "M680X_INS_DIVD", "M680X_INS_DIVQ",
 "M680X_INS_EDIV", "M680X_INS_EDIVS", "M680X_INS_EIM", "M680X_INS_EMACS",
 "M680X_INS_EMAXD", "M680X_INS_EMAXM", "M680X_INS_EMIND", "M680X_INS_EMINM",
 "M680X_INS_EMUL",
 "M680X_INS_EMULS", "M680X_INS_EOR", "M680X_INS_EORA", "M680X_INS_EORB",
 "M680X_INS_EORD", "M680X_INS_EORR", "M680X_INS_ETBL", "M680X_INS_EXG",
 "M680X_INS_FDIV", "M680X_INS_IBEQ", "M680X_INS_IBNE",
 "M680X_INS_IDIV", "M680X_INS_IDIVS", "M680X_INS_ILLGL", "M680X_INS_INC",
 "M680X_INS_INCA",
 "M680X_INS_INCB", "M680X_INS_INCD", "M680X_INS_INCE", "M680X_INS_INCF",
 "M680X_INS_INCW", "M680X_INS_INCX", "M680X_INS_INS", "M680X_INS_INX",
 "M680X_INS_INY", "M680X_INS_JMP", "M680X_INS_JSR", "M680X_INS_LBCC",
 "M680X_INS_LBCS", "M680X_INS_LBEQ", "M680X_INS_LBGE", "M680X_INS_LBGT",
 "M680X_INS_LBHI", "M680X_INS_LBLE", "M680X_INS_LBLS", "M680X_INS_LBLT",
 "M680X_INS_LBMI", "M680X_INS_LBNE", "M680X_INS_LBPL", "M680X_INS_LBRA",
 "M680X_INS_LBRN", "M680X_INS_LBSR", "M680X_INS_LBVC", "M680X_INS_LBVS",
 "M680X_INS_LDA", "M680X_INS_LDAA", "M680X_INS_LDAB", "M680X_INS_LDB",
 "M680X_INS_LDBT", "M680X_INS_LDD", "M680X_INS_LDE", "M680X_INS_LDF",
 "M680X_INS_LDHX", "M680X_INS_LDMD", "M680X_INS_LDQ", "M680X_INS_LDS",
 "M680X_INS_LDU", "M680X_INS_LDW", "M680X_INS_LDX", "M680X_INS_LDY",
 "M680X_INS_LEAS", "M680X_INS_LEAU", "M680X_INS_LEAX", "M680X_INS_LEAY",
 "M680X_INS_LSL", "M680X_INS_LSLA", "M680X_INS_LSLB", "M680X_INS_LSLD",
 "M680X_INS_LSLX", "M680X_INS_LSR", "M680X_INS_LSRA", "M680X_INS_LSRB",
 "M680X_INS_LSRD", "M680X_INS_LSRW", "M680X_INS_LSRX", "M680X_INS_MAXA",
 "M680X_INS_MAXM", "M680X_INS_MEM", "M680X_INS_MINA", "M680X_INS_MINM",
 "M680X_INS_MOV", "M680X_INS_MOVB", "M680X_INS_MOVW",
 "M680X_INS_MUL", "M680X_INS_MULD", "M680X_INS_NEG", "M680X_INS_NEGA",
 "M680X_INS_NEGB", "M680X_INS_NEGD", "M680X_INS_NEGX", "M680X_INS_NOP",
 "M680X_INS_NSA", "M680X_INS_OIM", "M680X_INS_ORA", "M680X_INS_ORAA",
 "M680X_INS_ORAB", "M680X_INS_ORB", "M680X_INS_ORCC", "M680X_INS_ORD",
 "M680X_INS_ORR", "M680X_INS_PSHA", "M680X_INS_PSHB", "M680X_INS_PSHC",
 "M680X_INS_PSHD", "M680X_INS_PSHH",
 "M680X_INS_PSHS", "M680X_INS_PSHSW", "M680X_INS_PSHU", "M680X_INS_PSHUW",
 "M680X_INS_PSHX", "M680X_INS_PSHY", "M680X_INS_PULA", "M680X_INS_PULB",
 "M680X_INS_PULC", "M680X_INS_PULD", "M680X_INS_PULH", "M680X_INS_PULS",
 "M680X_INS_PULSW", "M680X_INS_PULU",
 "M680X_INS_PULUW", "M680X_INS_PULX", "M680X_INS_PULY", "M680X_INS_REV",
 "M680X_INS_REVW", "M680X_INS_ROL",
 "M680X_INS_ROLA", "M680X_INS_ROLB", "M680X_INS_ROLD", "M680X_INS_ROLW",
 "M680X_INS_ROLX", "M680X_INS_ROR", "M680X_INS_RORA", "M680X_INS_RORB",
 "M680X_INS_RORD", "M680X_INS_RORW", "M680X_INS_RORX", "M680X_INS_RSP",
 "M680X_INS_RTC", "M680X_INS_RTI", "M680X_INS_RTS", "M680X_INS_SBA",
 "M680X_INS_SBC",
 "M680X_INS_SBCA", "M680X_INS_SBCB", "M680X_INS_SBCD", "M680X_INS_SBCR",
 "M680X_INS_SEC", "M680X_INS_SEI", "M680X_INS_SEV", "M680X_INS_SEX",
 "M680X_INS_SEXW", "M680X_INS_STA", "M680X_INS_STAA", "M680X_INS_STAB",
 "M680X_INS_STB", "M680X_INS_STBT", "M680X_INS_STD", "M680X_INS_STE",
 "M680X_INS_STF", "M680X_INS_STOP", "M680X_INS_STHX", "M680X_INS_STQ",
 "M680X_INS_STS", "M680X_INS_STU", "M680X_INS_STW", "M680X_INS_STX",
 "M680X_INS_STY", "M680X_INS_SUB", "M680X_INS_SUBA", "M680X_INS_SUBB",
 "M680X_INS_SUBD", "M680X_INS_SUBE", "M680X_INS_SUBF", "M680X_INS_SUBR",
 "M680X_INS_SUBW", "M680X_INS_SWI", "M680X_INS_SWI2", "M680X_INS_SWI3",
 "M680X_INS_SYNC", "M680X_INS_TAB", "M680X_INS_TAP", "M680X_INS_TAX",
 "M680X_INS_TBA", "M680X_INS_TBEQ", "M680X_INS_TBL", "M680X_INS_TBNE",
 "M680X_INS_TEST", "M680X_INS_TFM", "M680X_INS_TFR",
 "M680X_INS_TIM", "M680X_INS_TPA", "M680X_INS_TST", "M680X_INS_TSTA",
 "M680X_INS_TSTB", "M680X_INS_TSTD", "M680X_INS_TSTE", "M680X_INS_TSTF",
 "M680X_INS_TSTW", "M680X_INS_TSTX", "M680X_INS_TSX", "M680X_INS_TSY",
 "M680X_INS_TXA", "M680X_INS_TXS", "M680X_INS_TYS", "M680X_INS_WAI",
 "M680X_INS_WAIT", "M680X_INS_WAV", "M680X_INS_WAVR", "M680X_INS_XGDX",
 "M680X_INS_XGDY",
};

const char *s_access[] =
{
 "UNCHANGED", "READ", "WRITE", "READ | WRITE",
};

static void print_read_write_regs(cs_detail *detail)
{
  int i;

  if (detail->regs_read_count > 0)
  {
    printf("\treading from regs: ");

    for (i = 0; i < detail->regs_read_count; ++i)
    {
      if (i > 0)
        printf(", ");

      printf("%s", cs_reg_name(handle, detail->regs_read[i]));
    }

    printf("\n");
  }

  if (detail->regs_write_count > 0)
  {
    printf("\twriting to regs: ");

    for (i = 0; i < detail->regs_write_count; ++i)
    {
      if (i > 0)
        printf(", ");

      printf("%s", cs_reg_name(handle, detail->regs_write[i]));
    }

    printf("\n");
  }
}

static bool is_insn_address_relative(cs_insn *ins) {
  cs_detail *detail = ins->detail;
  cs_m680x *m680x = NULL;
  int i;

  if (detail == NULL)
    return false; // If not details availabe not detectable

  m680x = &detail->m680x;

  for (i = 0; i < m680x->op_count; i++)
  {
    if (m680x->operands[i].type == M680X_OP_RELATIVE)
      return true;
    if ((m680x->operands[i].type == M680X_OP_INDEXED) &&
        (m680x->operands[i].idx.base_reg == M680X_REG_PC))
      return true;
  }

  return false;
}

static void print_insn_detail(cs_insn *ins)
{
  cs_detail *detail = ins->detail;
  cs_m680x *m680x = NULL;
  int i;

  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (detail == NULL)
  {
    return;
  }

  m680x = &detail->m680x;

  if (m680x->op_count)
  {
    printf("\toperand_count: %u\n", m680x->op_count);
  }

  for (i = 0; i < m680x->op_count; i++)
  {
    cs_m680x_op *op = &(m680x->operands[i]);
    char *comment;

    switch ((int)op->type)
    {
      default:
        break;

      case M680X_OP_REGISTER:
        comment = "";
        if ((i == 0 && (m680x->flags & M680X_FIRST_OP_IN_MNEM)) ||
            (i == 1 && (m680x->flags & M680X_SECOND_OP_IN_MNEM)))
          comment = " (in mnemonic)";
        printf("\t\toperands[%u].type: REGISTER = %s%s\n", i,
               cs_reg_name(handle, op->reg), comment);
        break;

      case M680X_OP_INDEX:
        printf("\t\toperands[%u].type: INDEX = %u\n", i, op->index);
        break;

      case M680X_OP_IMMEDIATE:
        printf("\t\toperands[%u].type: IMMEDIATE = #%d\n", i, op->imm);
        break;

      case M680X_OP_DIRECT:
        printf("\t\toperands[%u].type: DIRECT = 0x%02X\n", i, op->direct_addr);
        break;

      case M680X_OP_EXTENDED:
        printf("\t\toperands[%u].type: EXTENDED %s = 0x%04X\n", i,
               op->ext.indirect ? "INDIRECT" : "", op->ext.address);
        break;

      case M680X_OP_RELATIVE:
        printf("\t\toperands[%u].type: RELATIVE = 0x%04X\n", i,
               op->rel.address);
        break;

      case M680X_OP_INDEXED:
        printf("\t\toperands[%u].type: INDEXED%s\n", i,
               (op->idx.flags & M680X_IDX_INDIRECT) ? " INDIRECT" : "");

        if (op->idx.base_reg != M680X_REG_INVALID)
          printf("\t\t\tbase register: %s\n", cs_reg_name(handle,
                 op->idx.base_reg));

        if (op->idx.offset_reg != M680X_REG_INVALID)
          printf("\t\t\toffset register: %s\n", cs_reg_name(handle,
                 op->idx.offset_reg));

        if ((op->idx.offset_bits != 0) &&
            (op->idx.offset_reg == M680X_REG_INVALID) &&
            !op->idx.inc_dec)
        {
          printf("\t\t\toffset: %d\n", op->idx.offset);
          if (op->idx.base_reg == M680X_REG_PC)
            printf("\t\t\toffset address: 0x%X\n", op->idx.offset_addr);
          printf("\t\t\toffset bits: %d\n", op->idx.offset_bits);
        }

        if (op->idx.inc_dec) {
          printf("\t\t\t%s", (op->idx.flags & M680X_IDX_POST_INC_DEC) ?
                              "post":"pre");
          if (op->idx.inc_dec > 0)
            printf(" increment: %d\n", op->idx.inc_dec);
          else
            printf(" decrement: %d\n", abs(op->idx.inc_dec));
        }

        break;
    }
    if (op->size != 0)
      printf("\t\t\tsize: %u\n", op->size);
    if (op->access != CS_AC_INVALID)
      printf("\t\t\taccess: %s\n", s_access[op->access]);
  }

  print_read_write_regs(detail);

  if (detail->groups_count)
  {
    int g;

    printf("\tgroups: ");
    for (g = 0; g < detail->groups_count; ++g) {
      if (g > 0)
        printf(", ");

      printf("%s", cs_group_name(handle, detail->groups[g]));
    }
    printf("\n");
  }

  printf("\n");
}

static bool consistency_checks()
{
  if (M680X_INS_ENDING != ARR_SIZE(s_insn_ids))
  {
    fprintf(stderr, "Internal error: Size mismatch in enum m680x_insn "
                    "and s_insn_ids\n");
    return false;
  }

  return true;
}

extern bool consistency_checks();

static void test(struct platform *platforms, size_t platform_count)
{
  uint64_t address = 0x1000;
  cs_insn *insn;
  size_t i;
  size_t count;
  char *nine_spaces = "         ";

  if (!consistency_checks())
    abort();

  for (i = 0; i < platform_count; i++)
  {
    cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);

    if (err)
    {
      printf("Failed on cs_open() with error returned: %u. Platform: %s\n",
            err, platforms[i].comment);
      abort();
    }

    if (platforms[i].detailed)
    {
      cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0,
                      &insn);

    if (count)
    {
      size_t j;

      printf("*********************\n");
      printf("Platform: %s\n", platforms[i].comment);
      print_string_hex("Code: ", platforms[i].code, platforms[i].size);
      printf("Disasm:\n");

      for (j = 0; j < count; j++)
      {
        if (is_insn_address_relative(&insn[j]))
          printf("0x%04X: ", (uint16_t)insn[j].address);
        else
          printf("        ");
        print_string_hex_short(insn[j].bytes, insn[j].size);
        printf("%.*s", 1 + ((5 - insn[j].size) * 2), nine_spaces);
        printf("%s", insn[j].mnemonic);
        if (strlen((char *)insn[j].op_str) != 0) {
          printf("%.*s", 1 + ((5 - (int)strlen(insn[j].mnemonic))),
                 nine_spaces);
       	  printf("%s", insn[j].op_str);
        }
       	printf("\n");
        if (platforms[i].detailed)
        {
          printf("\tinsn id: %s\n", (char *)&s_insn_ids[insn[j].id]);
        }
        print_insn_detail(&insn[j]);
      }

      printf("0x%04X\n", (uint16_t)insn[j - 1].address + insn[j - 1].size);

      // free memory allocated by cs_disasm()
      cs_free(insn, count);
    }
    else
    {
      printf("*********************\n");
      printf("Platform: %s\n", platforms[i].comment);
      print_string_hex("Code:", platforms[i].code, platforms[i].size);
      printf("ERROR: Failed to disasm given code!\n");
      abort();
    }

    printf("\n");

    cs_close(&handle);
  }
}
#endif

