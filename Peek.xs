#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define LANGDUMPMAX 4
/* #define fprintf		 */

static int loopDump;
void DumpLevel _((I32 level, SV *sv, I32 lim));

#define DBL_DIG	15   /* A guess that works lots of places */
#define fprintg(file,name,sv)	do {			\
	PerlIO_printf(file, "%*s%s = 0x%lx", level*2 - 2, "", name, (long)sv);	\
	if (sv && GvNAME(sv)) {				\
	  PerlIO_printf(file, "\t\"%s\"\n", GvNAME(sv));	\
	} else {					\
	  PerlIO_printf(file, "\n");				\
	} } while (0)
#define fprinth(file,name,sv)	do {			\
	PerlIO_printf(file, "%*s%s = 0x%lx", level*2 - 2, "", name, (long)sv);	\
	if (sv && HvNAME(sv)) {				\
	  PerlIO_printf(file, "\t\"%s\"\n", HvNAME(sv));	\
	} else {					\
	  PerlIO_printf(file, "\n");				\
	} } while (0)

static void
#ifdef I_STDARG
m_printf(I32 level, PerlIO *file, const char* pat,...)
#else
/*VARARGS0*/
void
m_printf(level,file,pat,va_alist)
    I32 level;
    PerlIO *file;
    const char *pat;
    va_dcl
#endif
{
    va_list args;
    
#ifdef I_STDARG
    va_start(args, pat);
#else
    va_start(args);
#endif
    PerlIO_printf(file, "%*s", level * 2 - 2, "");
    PerlIO_vprintf(file, pat, args);
    va_end(args);
}

static void
fprintgg(file, name, sv, level)
    PerlIO *file;
    char *name;
    GV *sv;
    int level;
{
	PerlIO_printf(file, "%*s%s = 0x%lx", level*2 - 2, "", name, (long)sv);
	if (sv && GvNAME(sv)) {
	  PerlIO_printf(file, "\t\"");
	  if (GvSTASH(sv) && HvNAME(GvSTASH(sv))) {
	    PerlIO_printf(file, "%s\" :: \"", HvNAME(GvSTASH(sv)));
	  }
	  PerlIO_printf(file, "%s\"\n", GvNAME(sv));
	} else {
	  PerlIO_printf(file, "\n");
	}
}


static void
fprintpv(file, pv, cur, len)
    PerlIO *file;
    char *pv;
    STRLEN cur;
    STRLEN len;
{
    SV  *pv_lim_sv = perl_get_sv("Devel::Peek::pv_limit", FALSE);
    STRLEN pv_lim = pv_lim_sv ? SvIV(pv_lim_sv) : 0;
    STRLEN out = 0;
    int truncated = 0;
    int nul_terminated = len > cur && pv[cur] == '\0';

    PerlIO_putc(file, '"');
    for (; cur--; pv++) {
	if (pv_lim && out >= pv_lim) {
            truncated++;
	    break;
        }
        if (isPRINT(*pv)) {
	    STRLEN len = 2;
            switch (*pv) {
		case '\t':
		    PerlIO_puts(file, "\\t"); break;
		case '\n':
		    PerlIO_puts(file, "\\n"); break;
		case '\r':
		    PerlIO_puts(file, "\\r"); break;
		case '\f':
		    PerlIO_puts(file, "\\f"); break;
		case '"':
		    PerlIO_puts(file, "\\\""); break;
		case '\\':
		    PerlIO_puts(file, "\\\\"); break;
		default:
		    PerlIO_putc(file, *pv);
		    len = 1;
                    break;
            }
            out += len;
        } else {
	    if (cur && isDIGIT(*(pv+1))) {
		PerlIO_printf(file, "\\%03o", *pv);
		out += 4;
	    } else {
		char tmpbuf[5];
		sprintf(tmpbuf, "\\%o", *pv);
		PerlIO_puts(file, tmpbuf);
		out += strlen(tmpbuf);
	    }
        }
    }
    PerlIO_putc(file, '"');
    if (truncated)
       PerlIO_puts(file, "...");
    if (nul_terminated)
       PerlIO_puts(file, "\\0");
}
 

void
DumpMagic(level,mg,lim)
I32 level;
MAGIC *mg;
I32 lim;
{
    for (; mg; mg = mg->mg_moremagic) {
 	m_printf(level, PerlIO_stderr(), "  MAGIC = %p\n", mg);
 	if (mg->mg_virtual) {
            MGVTBL *v = mg->mg_virtual;
 	    char *s = 0;
 	    if      (v == &vtbl_sv)         s = "vtbl_sv";
            else if (v == &vtbl_env)        s = "env";
            else if (v == &vtbl_envelem)    s = "envelem";
            else if (v == &vtbl_sig)        s = "sig";
            else if (v == &vtbl_sigelem)    s = "sigelem";
            else if (v == &vtbl_pack)       s = "pack";
            else if (v == &vtbl_packelem)   s = "packelem";
            else if (v == &vtbl_dbline)     s = "dbline";
            else if (v == &vtbl_isa)        s = "isa";
            else if (v == &vtbl_arylen)     s = "arylen";
            else if (v == &vtbl_glob)       s = "glob";
            else if (v == &vtbl_mglob)      s = "mglob";
            else if (v == &vtbl_nkeys)      s = "nkeys";
            else if (v == &vtbl_taint)      s = "taint";
            else if (v == &vtbl_substr)     s = "substr";
            else if (v == &vtbl_vec)        s = "vec";
            else if (v == &vtbl_pos)        s = "pos";
            else if (v == &vtbl_bm)         s = "bm";
            else if (v == &vtbl_fm)         s = "fm";
            else if (v == &vtbl_uvar)       s = "uvar";
            else if (v == &vtbl_defelem)    s = "defelem";
#ifdef USE_LOCALE_COLLATE
	    else if (v == &vtbl_collxfrm)   s = "collxfrm";
#endif
#ifdef OVERLOAD
	    else if (v == &vtbl_amagic)     s = "amagic";
	    else if (v == &vtbl_amagicelem) s = "amagicelem";
#endif
	    if (s) {
	        m_printf(level, PerlIO_stderr(), "    MG_VIRTUAL = &vtbl_%s\n", s);
	    } else {
	        m_printf(level, PerlIO_stderr(), "    MG_VIRTUAL = %p\n", v);
            }
        } else {
	   m_printf(level, PerlIO_stderr(), "    MG_VIRTUAL = 0\n");
	}
	if (mg->mg_private)
	    m_printf(level, PerlIO_stderr(), "    MG_PRIVATE = %d\n", mg->mg_private);
	if (isPRINT(mg->mg_type)) {
	   m_printf(level, PerlIO_stderr(), "    MG_TYPE = '%c'\n", mg->mg_type);
	} else {
	   m_printf(level, PerlIO_stderr(), "    MG_TYPE = '\%o'\n", mg->mg_type);
        }
        if (mg->mg_flags) {
            m_printf(level, PerlIO_stderr(), "    MG_FLAGS = 0x%02X\n", mg->mg_flags);
	    if (mg->mg_flags & MGf_TAINTEDDIR) {
	        m_printf(level, PerlIO_stderr(), "      TAINTEDDIR\n");
	    }
	    if (mg->mg_flags & MGf_REFCOUNTED) {
	        m_printf(level, PerlIO_stderr(), "      REFCOUNTED\n");
	    }
            if (mg->mg_flags & MGf_GSKIP) {
	        m_printf(level, PerlIO_stderr(), "      GSKIP\n");
	    }
	    if (mg->mg_flags & MGf_MINMATCH) {
	        m_printf(level, PerlIO_stderr(), "      MINMATCH\n");
	    }
        }
	if (mg->mg_obj) {
	    m_printf(level, PerlIO_stderr(), "    MG_OBJ = %p\n", mg->mg_obj);
	    if (mg->mg_flags & MGf_REFCOUNTED) {
	       loopDump++;
	       DumpLevel(level+2, mg->mg_obj, lim); /* MG is already +1 */
               loopDump--;
            }
	}
        if (mg->mg_ptr) {
	    m_printf(level, PerlIO_stderr(), "    MG_PTR = %p", mg->mg_ptr);
	    if (mg->mg_len) {
                PerlIO_putc(PerlIO_stderr(), ' ');
                fprintpv(PerlIO_stderr(), mg->mg_ptr, mg->mg_len, 0);
            }
            PerlIO_putc(PerlIO_stderr(), '\n');
        }
        if (mg->mg_len)
	    m_printf(level, PerlIO_stderr(), "    MG_LEN = %d\n", mg->mg_len);
    }
}

void
Dump(sv,lim)
SV *sv;
I32 lim;
{
    DumpLevel(0,sv,lim);
}

void
DumpLevel(level,sv,lim)
I32 level;
SV *sv;
I32 lim;
{
    char tmpbuf[1024];
    char *d = tmpbuf;
    I32 count;
    U32 flags;
    U32 type;

    level++;
    if (!sv) {
	m_printf(level, PerlIO_stderr(), "SV = 0\n");
	return;
    }

    flags = SvFLAGS(sv);
    type = SvTYPE(sv);

    sprintf(d, "(0x%lx)\n%*s  REFCNT = %ld\n%*s  FLAGS = (",
	    (unsigned long)SvANY(sv), 2*level - 2, "", (long)SvREFCNT(sv),
	    2*level - 2, "");
    d += strlen(d);
    if (flags & SVs_PADBUSY)	strcat(d, "PADBUSY,");
    if (flags & SVs_PADTMP)	strcat(d, "PADTMP,");
    if (flags & SVs_PADMY)	strcat(d, "PADMY,");
    if (flags & SVs_TEMP)	strcat(d, "TEMP,");
    if (flags & SVs_OBJECT)	strcat(d, "OBJECT,");
    if (flags & SVs_GMG)	strcat(d, "GMG,");
    if (flags & SVs_SMG)	strcat(d, "SMG,");
    if (flags & SVs_RMG)	strcat(d, "RMG,");
    d += strlen(d);

    if (flags & SVf_IOK)	strcat(d, "IOK,");
    if (flags & SVf_NOK)	strcat(d, "NOK,");
    if (flags & SVf_POK)	strcat(d, "POK,");
    if (flags & SVf_ROK)	strcat(d, "ROK,");
    if (flags & SVf_OOK)	strcat(d, "OOK,");
    if (flags & SVf_FAKE)	strcat(d, "FAKE,");
    if (flags & SVf_READONLY)	strcat(d, "READONLY,");
    d += strlen(d);

    if (flags & SVp_IOK)	strcat(d, "pIOK,");
    if (flags & SVp_NOK)	strcat(d, "pNOK,");
    if (flags & SVp_POK)	strcat(d, "pPOK,");
    if (flags & SVp_SCREAM)	strcat(d, "SCREAM,");

    switch (type) {
    case SVt_PVFM:
    case SVt_PVCV:
#ifdef SVpcv_ANON
      if (flags & SVpcv_ANON)	strcat(d, "ANON,");
      if (flags & SVpcv_UNIQUE)       strcat(d, "UNIQUE,");
      if (flags & SVpcv_CLONE)	strcat(d, "CLONE,");
      if (flags & SVpcv_CLONED)	strcat(d, "CLONED,");
      if (flags & SVpcv_NODEBUG) strcat(d, "NODEBUG,");
#else
      if (CvANON(sv))	strcat(d, "ANON,");
      if (CvUNIQUE(sv))       strcat(d, "UNIQUE,");
      if (CvCLONE(sv))	strcat(d, "CLONE,");
      if (CvCLONED(sv))	strcat(d, "CLONED,");
      if (CvNODEBUG(sv)) strcat(d, "NODEBUG,");
#endif 
      break;
    case SVt_PVGV:
#ifdef SVpgv_MULTI
      if (flags & SVpgv_MULTI) strcat(d, "MULTI,");
#else
	if (GvINTRO(sv))	strcat(d, "INTRO,");
	if (GvMULTI(sv))	strcat(d, "MULTI,");
	if (GvASSUMECV(sv))	strcat(d, "ASSUMECV,");
	if (GvIMPORTED(sv)) {
	    strcat(d, "IMPORT");
	    if (GvIMPORTED(sv) == GVf_IMPORTED)
		strcat(d, "ALL,");
	    else {
		strcat(d, "(");
		if (GvIMPORTED_SV(sv))	strcat(d, " SV");
		if (GvIMPORTED_AV(sv))	strcat(d, " AV");
		if (GvIMPORTED_HV(sv))	strcat(d, " HV");
		if (GvIMPORTED_CV(sv))	strcat(d, " CV");
		strcat(d, " ),");
	    }
	}
	break;
    case SVt_PVBM:
	if (SvTAIL(sv))	strcat(d, "TAIL,");
	if (SvCOMPILED(sv))	strcat(d, "COMPILED,");
	break;
    case SVt_PVHV:
	if (HvSHAREKEYS(sv))	strcat(d, "SHAREKEYS,");
	if (HvLAZYDEL(sv))	strcat(d, "LAZYDEL,");
	break;
#endif
    }

    d += strlen(d);
    if (d[-1] == ',')
	d--;
    *d++ = ')';
    *d = '\0';

    m_printf(level, PerlIO_stderr(), "SV = ");
    switch (type) {
    case SVt_NULL:
	PerlIO_printf(PerlIO_stderr(),"NULL%s\n", tmpbuf);
	return;
    case SVt_IV:
	PerlIO_printf(PerlIO_stderr(),"IV%s\n", tmpbuf);
	break;
    case SVt_NV:
	PerlIO_printf(PerlIO_stderr(),"NV%s\n", tmpbuf);
	break;
    case SVt_RV:
	PerlIO_printf(PerlIO_stderr(),"RV%s\n", tmpbuf);
	break;
    case SVt_PV:
	PerlIO_printf(PerlIO_stderr(),"PV%s\n", tmpbuf);
	break;
    case SVt_PVIV:
	PerlIO_printf(PerlIO_stderr(),"PVIV%s\n", tmpbuf);
	break;
    case SVt_PVNV:
	PerlIO_printf(PerlIO_stderr(),"PVNV%s\n", tmpbuf);
	break;
    case SVt_PVBM:
	PerlIO_printf(PerlIO_stderr(),"PVBM%s\n", tmpbuf);
	break;
    case SVt_PVMG:
	PerlIO_printf(PerlIO_stderr(),"PVMG%s\n", tmpbuf);
	break;
    case SVt_PVLV:
	PerlIO_printf(PerlIO_stderr(),"PVLV%s\n", tmpbuf);
	break;
    case SVt_PVAV:
	PerlIO_printf(PerlIO_stderr(),"PVAV%s\n", tmpbuf);
	break;
    case SVt_PVHV:
	PerlIO_printf(PerlIO_stderr(),"PVHV%s\n", tmpbuf);
	break;
    case SVt_PVCV:
	PerlIO_printf(PerlIO_stderr(),"PVCV%s\n", tmpbuf);
	break;
    case SVt_PVGV:
	PerlIO_printf(PerlIO_stderr(),"PVGV%s\n", tmpbuf);
	break;
    case SVt_PVFM:
	PerlIO_printf(PerlIO_stderr(),"PVFM%s\n", tmpbuf);
	break;
    case SVt_PVIO:
	PerlIO_printf(PerlIO_stderr(),"PVIO%s\n", tmpbuf);
	break;
    default:
	PerlIO_printf(PerlIO_stderr(),"UNKNOWN%s\n", tmpbuf);
	return;
    }
    if ((type >= SVt_PVIV && type != SVt_PVHV) || type == SVt_IV) {
	m_printf(level, PerlIO_stderr(), "  IV = %ld", (long)SvIVX(sv));
	if (SvOOK(sv))
	    PerlIO_printf(PerlIO_stderr(), "  (OFFSET)");
	PerlIO_putc(PerlIO_stderr(), '\n');
    }
    if (type >= SVt_PVNV || type == SVt_NV)
	m_printf(level, PerlIO_stderr(), "  NV = %.*g\n", DBL_DIG, SvNVX(sv));
    if (SvROK(sv)) {
	m_printf(level, PerlIO_stderr(), "  RV = 0x%lx\n", (long)SvRV(sv));
	if (loopDump < lim) {
	  loopDump++;
	  DumpLevel(level + 1, SvRV(sv),lim); /* Indent wrt RV = .  */
	  loopDump--;
	}
	return;
    }
    if (type < SVt_PV)
	return;
    if (type <= SVt_PVLV) {
	if (SvPVX(sv)) {
	    m_printf(level, PerlIO_stderr(),"  PV = 0x%lx ", (long)SvPVX(sv));
	    if (SvOOK(sv)) {
		PerlIO_puts(PerlIO_stderr(), "( ");
		fprintpv(PerlIO_stderr(), SvPVX(sv) - SvIVX(sv), SvIVX(sv), 0);
		PerlIO_puts(PerlIO_stderr(), " . ) ");
	    }
	    fprintpv(PerlIO_stderr(), SvPVX(sv), SvCUR(sv), SvLEN(sv));
	    PerlIO_printf(PerlIO_stderr(), "\n%*s  CUR = %ld\n%*s  LEN = %ld\n",
		                           2*level - 2, "", (long)SvCUR(sv),
	                                   2*level - 2, "", (long)SvLEN(sv));
	} else
	    m_printf(level, PerlIO_stderr(), "  PV = 0\n");
    }
    if (type >= SVt_PVMG) {
	if (SvMAGIC(sv))
            DumpMagic(level, SvMAGIC(sv), lim);
	if (SvSTASH(sv))
	    fprinth(PerlIO_stderr(), "  STASH", SvSTASH(sv));
    }
    switch (type) {
    case SVt_PVLV:
	m_printf(level, PerlIO_stderr(), "  TYPE = %c\n", LvTYPE(sv));
	m_printf(level, PerlIO_stderr(), "  TARGOFF = %ld\n", (long)LvTARGOFF(sv));
	m_printf(level, PerlIO_stderr(), "  TARGLEN = %ld\n", (long)LvTARGLEN(sv));
	m_printf(level, PerlIO_stderr(), "  TARG = 0x%lx\n", (long)LvTARG(sv));
	DumpLevel(level, LvTARG(sv),lim);
	break;
    case SVt_PVAV:
	m_printf(level, PerlIO_stderr(), "  ARRAY = 0x%lx\n", (long)AvARRAY(sv));
	m_printf(level, PerlIO_stderr(), "  ALLOC = 0x%lx\n", (long)AvALLOC(sv));
	m_printf(level, PerlIO_stderr(), "  FILL = %ld\n", (long)AvFILL(sv));
	m_printf(level, PerlIO_stderr(), "  MAX = %ld\n", (long)AvMAX(sv));
	m_printf(level, PerlIO_stderr(), "  ARYLEN = 0x%lx\n", (long)AvARYLEN(sv));

	flags = AvFLAGS(sv);
	d = tmpbuf;
	*d = '\0';
	if (flags & AVf_REAL)	strcat(d, ",REAL");
	if (flags & AVf_REIFY)	strcat(d, ",REIFY");
	if (flags & AVf_REUSED)	strcat(d, ",REUSED");
	m_printf(level, PerlIO_stderr(), "  FLAGS = (%s)\n", (*d ? d + 1 : ""));

	if (loopDump < lim && av_len((AV*)sv) >= 0) {
	  loopDump++;
	  for (count = 0; count <=  av_len((AV*)sv) && count < lim; 
	       count++) {
	    SV** elt = av_fetch((AV*)sv,count,0);

	    m_printf(level, PerlIO_stderr(), "Elt No. %ld  0x%lx\n", (long)count, *elt);
	    if (elt) DumpLevel(level,*elt,lim);
	  }
	  loopDump--;
	}
	break;
    case SVt_PVHV:
	m_printf(level, PerlIO_stderr(), "  ARRAY = 0x%lx\n",(long)HvARRAY(sv));
	m_printf(level, PerlIO_stderr(), "  KEYS = %ld\n", (long)HvKEYS(sv));
	m_printf(level, PerlIO_stderr(), "  FILL = %ld\n", (long)HvFILL(sv));
	m_printf(level, PerlIO_stderr(), "  MAX = %ld\n", (long)HvMAX(sv));
	m_printf(level, PerlIO_stderr(), "  RITER = %ld\n", (long)HvRITER(sv));
	m_printf(level, PerlIO_stderr(), "  EITER = 0x%lx\n",(long) HvEITER(sv));
	if (HvPMROOT(sv))
	    m_printf(level, PerlIO_stderr(), "  PMROOT = 0x%lx\n",(long)HvPMROOT(sv));
	if (HvNAME(sv))
	    m_printf(level, PerlIO_stderr(), "  NAME = \"%s\"\n", HvNAME(sv));
	if (loopDump < lim && !HvEITER(sv)) { /* Try to preserve iterator */
	  HE *he;
	  HV *hv = (HV*)sv;
	  int count = lim - loopDump;
	  I32 len;
	  SV *elt;
	  char *key;

	  loopDump--;
	  hv_iterinit(hv);
	  while ((elt = hv_iternextsv(hv,&key,&len)) && count--) {
	    m_printf(level, PerlIO_stderr(), "Elt ");
            fprintpv(PerlIO_stderr(), key, len, 0);
            PerlIO_printf(PerlIO_stderr(), " => 0x%lx\n", elt);
	    DumpLevel(level,elt,lim);
	  }
	  hv_iterinit(hv);		/* Return to status quo */
	  loopDump--;
	}
	break;
    case SVt_PVFM:
    case SVt_PVCV:
	if (SvPOK(sv)) m_printf(level, PerlIO_stderr(), "  PROTOTYPE = \"%s\"\n",
			       SvPV(sv,na));
	fprinth(PerlIO_stderr(), "  COMP_STASH", CvSTASH(sv));
	m_printf(level, PerlIO_stderr(), "  START = 0x%lx\n", (long)CvSTART(sv));
	m_printf(level, PerlIO_stderr(), "  ROOT = 0x%lx\n", (long)CvROOT(sv));
	m_printf(level, PerlIO_stderr(), "  XSUB = 0x%lx\n", (long)CvXSUB(sv));
	m_printf(level, PerlIO_stderr(), "  XSUBANY = %ld\n", (long)CvXSUBANY(sv).any_i32);
	fprintgg(PerlIO_stderr(), "  GVGV::GV", CvGV(sv), level);
	fprintg(PerlIO_stderr(), "  FILEGV", CvFILEGV(sv));
	m_printf(level, PerlIO_stderr(), "  DEPTH = %ld\n", (long)CvDEPTH(sv));
	m_printf(level, PerlIO_stderr(), "  PADLIST = 0x%lx\n", (long)CvPADLIST(sv));
	m_printf(level, PerlIO_stderr(), "  OUTSIDE = 0x%lx\n", (long)CvOUTSIDE(sv));
#ifdef USE_THREADS
	m_printf(level, PerlIO_stderr(), "  MUTEXP = 0x%lx\n", (long)CvMUTEXP(sv));
	m_printf(level, PerlIO_stderr(), "  OWNER = 0x%lx\n", (long)CvOWNER(sv));
#endif /* USE_THREADS */
	m_printf(level, PerlIO_stderr(), "  FLAGS = 0x%lx\n",
		      (unsigned long)CvFLAGS(sv));
	if (type == SVt_PVFM)
	    m_printf(level, PerlIO_stderr(), "  LINES = %ld\n", (long)FmLINES(sv));
	break;
    case SVt_PVGV:
	m_printf(level, PerlIO_stderr(), "  NAME = \"%s\"\n", GvNAME(sv));
	m_printf(level, PerlIO_stderr(), "  NAMELEN = %ld\n", (long)GvNAMELEN(sv));
	fprinth(PerlIO_stderr(), "  GvSTASH", GvSTASH(sv));
	m_printf(level, PerlIO_stderr(), "  GP = 0x%lx\n", (long)GvGP(sv));
	m_printf(level, PerlIO_stderr(), "    SV = 0x%lx\n", (long)GvSV(sv));
	m_printf(level, PerlIO_stderr(), "    REFCNT = %ld\n", (long)GvREFCNT(sv));
	m_printf(level, PerlIO_stderr(), "    IO = 0x%lx\n", (long)GvIOp(sv));
	m_printf(level, PerlIO_stderr(), "    FORM = 0x%lx\n", (long)GvFORM(sv));
	m_printf(level, PerlIO_stderr(), "    AV = 0x%lx\n", (long)GvAV(sv));
	m_printf(level, PerlIO_stderr(), "    HV = 0x%lx\n", (long)GvHV(sv));
	m_printf(level, PerlIO_stderr(), "    CV = 0x%lx\n", (long)GvCV(sv));
	m_printf(level, PerlIO_stderr(), "    CVGEN = 0x%lx\n", (long)GvCVGEN(sv));
	m_printf(level, PerlIO_stderr(), "    LASTEXPR = %ld\n", (long)GvLASTEXPR(sv));
	m_printf(level, PerlIO_stderr(), "    LINE = %ld\n", (long)GvLINE(sv));
	m_printf(level, PerlIO_stderr(), "    FLAGS = 0x%x\n", (int)GvFLAGS(sv));
	fprintg(PerlIO_stderr(), "    FILEGV", GvFILEGV(sv));
	fprintg(PerlIO_stderr(), "    EGV", GvEGV(sv));
	break;
    case SVt_PVIO:
	m_printf(level, PerlIO_stderr(), "  IFP = 0x%lx\n", (long)IoIFP(sv));
	m_printf(level, PerlIO_stderr(), "  OFP = 0x%lx\n", (long)IoOFP(sv));
	m_printf(level, PerlIO_stderr(), "  DIRP = 0x%lx\n", (long)IoDIRP(sv));
	m_printf(level, PerlIO_stderr(), "  LINES = %ld\n", (long)IoLINES(sv));
	m_printf(level, PerlIO_stderr(), "  PAGE = %ld\n", (long)IoPAGE(sv));
	m_printf(level, PerlIO_stderr(), "  PAGE_LEN = %ld\n", (long)IoPAGE_LEN(sv));
	m_printf(level, PerlIO_stderr(), "  LINES_LEFT = %ld\n", (long)IoLINES_LEFT(sv));
	m_printf(level, PerlIO_stderr(), "  TOP_NAME = \"%s\"\n", IoTOP_NAME(sv));
	fprintg(PerlIO_stderr(), "  TOP_GV", IoTOP_GV(sv));
	m_printf(level, PerlIO_stderr(), "  FMT_NAME = \"%s\"\n", IoFMT_NAME(sv));
	fprintg(PerlIO_stderr(), "  FMT_GV", IoFMT_GV(sv));
	m_printf(level, PerlIO_stderr(), "  BOTTOM_NAME = \"%s\"\n", IoBOTTOM_NAME(sv));
	fprintg(PerlIO_stderr(), "  BOTTOM_GV", IoBOTTOM_GV(sv));
	m_printf(level, PerlIO_stderr(), "  SUBPROCESS = %ld\n", (long)IoSUBPROCESS(sv));
	m_printf(level, PerlIO_stderr(), "  TYPE = %c\n", IoTYPE(sv));
	m_printf(level, PerlIO_stderr(), "  FLAGS = 0x%lx\n", (long)IoFLAGS(sv));
	break;
    }
}

#ifdef PURIFY
#define DeadCode() NULL
#else

SV *
DeadCode()
{
    SV* sva;
    SV* sv, *dbg;
    SV* ret = newRV_noinc((SV*)newAV());
    register SV* svend;
    int tm = 0, tref = 0, ts = 0, ta = 0, tas = 0;

    for (sva = sv_arenaroot; sva; sva = (SV*)SvANY(sva)) {
	svend = &sva[SvREFCNT(sva)];
	for (sv = sva + 1; sv < svend; ++sv) {
	    if (SvTYPE(sv) == SVt_PVCV) {
		CV *cv = (CV*)sv;
		AV* padlist = CvPADLIST(cv), *argav;
		SV** svp;
		SV** pad;
		int i = 0, j, levelm, totm = 0, levelref, totref = 0;
		int levels, tots = 0, levela, tota = 0, levelas, totas = 0;
		int dumpit = 0;

		if (CvXSUB(sv)) {
		    continue;		/* XSUB */
		}
		if (!CvGV(sv)) {
		    continue;		/* file-level scope. */
		}
		if (!CvROOT(cv)) {
		    /* PerlIO_printf(PerlIO_stderr(), "  no root?!\n"); */
		    continue;		/* autoloading stub. */
		}
		fprintgg(PerlIO_stderr(), "GVGV::GV", CvGV(sv), 0);
		if (CvDEPTH(cv)) {
		    PerlIO_printf(PerlIO_stderr(), "  busy\n");
		    continue;
		}
		svp = AvARRAY(padlist);
		while (++i <= AvFILL(padlist)) { /* Depth. */
		    SV **args;
		    
		    pad = AvARRAY((AV*)svp[i]);
		    argav = (AV*)pad[0];
		    if (!argav || (SV*)argav == &sv_undef) {
			PerlIO_printf(PerlIO_stderr(), "    closure-template\n");
			continue;
		    }
		    args = AvARRAY(argav);
		    levelm = levels = levelref = levelas = 0;
		    levela = sizeof(SV*) * (AvMAX(argav) + 1);
		    if (AvREAL(argav)) {
			for (j = 0; j < AvFILL(argav); j++) {
			    if (SvROK(args[j])) {
				PerlIO_printf(PerlIO_stderr(), "     ref in args!\n");
				levelref++;
			    }
			    /* else if (SvPOK(args[j]) && SvPVX(args[j])) { */
			    else if (SvTYPE(args[j]) >= SVt_PV && SvLEN(args[j])) {
				levelas += SvLEN(args[j])/SvREFCNT(args[j]);
			    }
			}
		    }
		    for (j = 1; j < AvFILL((AV*)svp[1]); j++) {	/* Vars. */
			if (SvROK(pad[j])) {
			    levelref++;
			    DumpLevel(0,pad[j],4);
			    dumpit = 1;
			}
			/* else if (SvPOK(pad[j]) && SvPVX(pad[j])) { */
			else if (SvTYPE(pad[j]) >= SVt_PVAV) {
			    if (!SvPADMY(pad[j])) {
				levelref++;
				DumpLevel(0,pad[j],4);
				dumpit = 1;
			    }
			}
			else if (SvTYPE(pad[j]) >= SVt_PV && SvLEN(pad[j])) {
			    int db_len = SvLEN(pad[j]);
			    SV *db_sv = pad[j];
			    levels++;
			    levelm += SvLEN(pad[j])/SvREFCNT(pad[j]);
				/* Dump(pad[j],4); */
			}
		    }
		    PerlIO_printf(PerlIO_stderr(), "    level %i: refs: %i, strings: %i in %i,\n        argsarray: %i, argsstrings: %i\n", 
			    i, levelref, levelm, levels, levela, levelas);
		    totm += levelm;
		    tota += levela;
		    totas += levelas;
		    tots += levels;
		    totref += levelref;
		    if (dumpit) DumpLevel(0,(SV*)cv,2);
		}
		if (AvFILL(padlist) > 1) {
		    PerlIO_printf(PerlIO_stderr(), "  total: refs: %i, strings: %i in %i\n        argsarrays: %i, argsstrings: %i\n", 
			    totref, totm, tots, tota, totas);
		}
		tref += totref;
		tm += totm;
		ts += tots;
		ta += tota;
		tas += totas;
	    }
	}
    }
    PerlIO_printf(PerlIO_stderr(), "total: refs: %i, strings: %i in %i\nargsarray: %i, argsstrings: %i\n", tref, tm, ts, ta, tas);

    return ret;
}
#endif /* !PURIFY */

#ifdef DEBUGGING_MSTATS
#   define mstat(str) dump_mstats(str)
#else
#   define mstat(str) \
	PerlIO_printf(PerlIO_stderr(), "%s: perl not compiled with DEBUGGING_MSTATS\n",str);
#endif

MODULE = Devel::Peek		PACKAGE = Devel::Peek

void
mstat(str="Devel::Peek::mstat: ")
char *str

void
Dump(sv,lim=4)
SV *	sv
I32	lim

void
DumpArray(lim,...)
I32	lim
 PPCODE:
    {
	long i;

	for (i=1; i<items; i++) {
	    PerlIO_printf(PerlIO_stderr(), "Elt No. %ld  0x%lx\n", i - 1, ST(i));
	    Dump(ST(i), lim);
	}
    }

I32
SvREFCNT(sv)
SV *	sv

 
# PPCODE needed since otherwise sv_2mortal is inserted that will kill
# the value.


SV *
SvREFCNT_inc(sv)
SV *	sv
 PPCODE:
    {
	RETVAL = SvREFCNT_inc(sv);
	PUSHs(RETVAL);
    }

# PPCODE needed since by default it is void

SV *
SvREFCNT_dec(sv)
SV *	sv
 PPCODE:
    {
	SvREFCNT_dec(sv);
	PUSHs(sv);
    }

SV *
DeadCode()
