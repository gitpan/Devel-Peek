#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define LANGDUMPMAX 4

static int loopDump;

#define DBL_DIG	15   /* A guess that works lots of places */
#define fprintg(file,name,sv)	do {			\
	PerlIO_printf(file, "%s = 0x%lx", name, (long)sv);	\
	if (sv && GvNAME(sv)) {				\
	  PerlIO_printf(file, "\t\"%s\"\n", GvNAME(sv));	\
	} else {					\
	  PerlIO_printf(file, "\n");				\
	} } while (0)
#define fprinth(file,name,sv)	do {			\
	PerlIO_printf(file, "%s = 0x%lx", name, (long)sv);	\
	if (sv && HvNAME(sv)) {				\
	  PerlIO_printf(file, "\t\"%s\"\n", HvNAME(sv));	\
	} else {					\
	  PerlIO_printf(file, "\n");				\
	} } while (0)

void
fprintgg(FILE *file, char *name, GV *sv)
{
	PerlIO_printf(file, "%s = 0x%lx", name, (long)sv);
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

void
Dump(sv,lim)
SV *sv;
I32 lim;
{
    char tmpbuf[1024];
    char *d = tmpbuf;
    I32 count;
    U32 flags;
    U32 type;

    if (!sv) {
	PerlIO_printf(PerlIO_stderr(), "SV = 0\n");
	return;
    }
    
    flags = SvFLAGS(sv);
    type = SvTYPE(sv);

    sprintf(d, "(0x%lx)\n  REFCNT = %ld\n  FLAGS = (",
	(unsigned long)SvANY(sv), (long)SvREFCNT(sv));
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

#ifdef OVERLOAD
    if (flags & SVf_AMAGIC)	strcat(d, "OVERLOAD,");
#endif /* OVERLOAD */
    if (flags & SVp_IOK)	strcat(d, "pIOK,");
    if (flags & SVp_NOK)	strcat(d, "pNOK,");
    if (flags & SVp_POK)	strcat(d, "pPOK,");
    if (flags & SVp_SCREAM)	strcat(d, "SCREAM,");

    switch (type) {
    case SVt_PVCV:
#ifdef SVpcv_ANON
      if (flags & SVpcv_ANON)	strcat(d, "ANON,");
      if (flags & SVpcv_CLONE)	strcat(d, "CLONE,");
      if (flags & SVpcv_CLONED)	strcat(d, "CLONED,");
#else
      if (CvANON(sv))	strcat(d, "ANON,");
      if (CvCLONE(sv))	strcat(d, "CLONE,");
      if (CvCLONED(sv))	strcat(d, "CLONED,");
#endif 
      break;
    case SVt_PVGV:
#ifdef SVpgv_MULTI
      if (flags & SVpgv_MULTI) strcat(d, "MULTI,");
#else
      if (GvMULTI(sv))         strcat(d, "MULTI,");
#endif
    }

    d += strlen(d);
    if (d[-1] == ',')
	d--;
    *d++ = ')';
    *d = '\0';

    PerlIO_printf(PerlIO_stderr(), "SV = ");
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
    if (type >= SVt_PVIV || type == SVt_IV)
	PerlIO_printf(PerlIO_stderr(), "  IV = %ld\n", (long)SvIVX(sv));
    if (type >= SVt_PVNV || type == SVt_NV)
	PerlIO_printf(PerlIO_stderr(), "  NV = %.*g\n", DBL_DIG, SvNVX(sv));
    if (SvROK(sv)) {
	PerlIO_printf(PerlIO_stderr(), "  RV = 0x%lx\n", (long)SvRV(sv));
	if (loopDump < lim) {
	  loopDump++;
	  Dump(SvRV(sv),lim);
	  loopDump--;
	}
	return;
    }
    if (type < SVt_PV)
	return;
    if (type <= SVt_PVLV) {
	if (SvPVX(sv))
	    PerlIO_printf(PerlIO_stderr(), "  PV = 0x%lx \"%s\"\n  CUR = %ld\n  LEN = %ld\n",
		(long)SvPVX(sv), SvPVX(sv), (long)SvCUR(sv), (long)SvLEN(sv));
	else
	    PerlIO_printf(PerlIO_stderr(), "  PV = 0\n");
    }
    if (type >= SVt_PVMG) {
	if (SvMAGIC(sv)) {
	    PerlIO_printf(PerlIO_stderr(), "  MAGIC = 0x%lx\n", (long)SvMAGIC(sv));
	}
	if (SvSTASH(sv))
	    fprinth(PerlIO_stderr(), "  STASH", SvSTASH(sv));
    }
    switch (type) {
    case SVt_PVLV:
	PerlIO_printf(PerlIO_stderr(), "  TYPE = %c\n", LvTYPE(sv));
	PerlIO_printf(PerlIO_stderr(), "  TARGOFF = %ld\n", (long)LvTARGOFF(sv));
	PerlIO_printf(PerlIO_stderr(), "  TARGLEN = %ld\n", (long)LvTARGLEN(sv));
	PerlIO_printf(PerlIO_stderr(), "  TARG = 0x%lx\n", (long)LvTARG(sv));
	Dump(LvTARG(sv),lim);
	break;
    case SVt_PVAV:
	PerlIO_printf(PerlIO_stderr(), "  ARRAY = 0x%lx\n", (long)AvARRAY(sv));
	PerlIO_printf(PerlIO_stderr(), "  ALLOC = 0x%lx\n", (long)AvALLOC(sv));
	PerlIO_printf(PerlIO_stderr(), "  FILL = %ld\n", (long)AvFILL(sv));
	PerlIO_printf(PerlIO_stderr(), "  MAX = %ld\n", (long)AvMAX(sv));
	PerlIO_printf(PerlIO_stderr(), "  ARYLEN = 0x%lx\n", (long)AvARYLEN(sv));
	if (AvREAL(sv))
	    PerlIO_printf(PerlIO_stderr(), "  FLAGS = (REAL)\n");
	else
	    PerlIO_printf(PerlIO_stderr(), "  FLAGS = ()\n");
	if (loopDump < lim && av_len((AV*)sv) >= 0) {
	  loopDump++;
	  for (count = 0; count <=  av_len((AV*)sv) && count < lim; 
	       count++) {
	    SV** elt = av_fetch((AV*)sv,count,0);

	    PerlIO_printf(PerlIO_stderr(), "Elt No. %ld  0x%lx\n", (long)count, *elt);
	    if (elt) Dump(*elt,lim);
	  }
	  loopDump--;
	}
	break;
    case SVt_PVHV:
	PerlIO_printf(PerlIO_stderr(), "  ARRAY = 0x%lx\n",(long)HvARRAY(sv));
	PerlIO_printf(PerlIO_stderr(), "  KEYS = %ld\n", (long)HvKEYS(sv));
	PerlIO_printf(PerlIO_stderr(), "  FILL = %ld\n", (long)HvFILL(sv));
	PerlIO_printf(PerlIO_stderr(), "  MAX = %ld\n", (long)HvMAX(sv));
	PerlIO_printf(PerlIO_stderr(), "  RITER = %ld\n", (long)HvRITER(sv));
	PerlIO_printf(PerlIO_stderr(), "  EITER = 0x%lx\n",(long) HvEITER(sv));
	if (HvPMROOT(sv))
	    PerlIO_printf(PerlIO_stderr(), "  PMROOT = 0x%lx\n",(long)HvPMROOT(sv));
	if (HvNAME(sv))
	    PerlIO_printf(PerlIO_stderr(), "  NAME = \"%s\"\n", HvNAME(sv));
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
	    PerlIO_printf(PerlIO_stderr(), "Elt \"%s\" => 0x%lx\n", key, elt);
	    Dump(elt,lim);
	  }
	  hv_iterinit(hv);		/* Return to status quo */
	  loopDump--;
	}
	break;
    case SVt_PVFM:
    case SVt_PVCV:
	if (SvPOK(sv)) PerlIO_printf(PerlIO_stderr(), "  PROTOTYPE = \"%s\"\n",
			       SvPV(sv,na));
	fprinth(PerlIO_stderr(), "  COMP_STASH", CvSTASH(sv));
	PerlIO_printf(PerlIO_stderr(), "  START = 0x%lx\n", (long)CvSTART(sv));
	PerlIO_printf(PerlIO_stderr(), "  ROOT = 0x%lx\n", (long)CvROOT(sv));
	PerlIO_printf(PerlIO_stderr(), "  XSUB = 0x%lx\n", (long)CvXSUB(sv));
	PerlIO_printf(PerlIO_stderr(), "  XSUBANY = %ld\n", (long)CvXSUBANY(sv).any_i32);
	fprintgg(PerlIO_stderr(), "  GVGV::GV", CvGV(sv));
	fprintg(PerlIO_stderr(), "  FILEGV", CvFILEGV(sv));
	PerlIO_printf(PerlIO_stderr(), "  DEPTH = %ld\n", (long)CvDEPTH(sv));
	PerlIO_printf(PerlIO_stderr(), "  PADLIST = 0x%lx\n", (long)CvPADLIST(sv));
	if (type == SVt_PVFM)
	    PerlIO_printf(PerlIO_stderr(), "  LINES = %ld\n", (long)FmLINES(sv));
	break;
    case SVt_PVGV:
	PerlIO_printf(PerlIO_stderr(), "  NAME = \"%s\"\n", GvNAME(sv));
	PerlIO_printf(PerlIO_stderr(), "  NAMELEN = %ld\n", (long)GvNAMELEN(sv));
	fprinth(PerlIO_stderr(), "  STASH", GvSTASH(sv));
	PerlIO_printf(PerlIO_stderr(), "  GP = 0x%lx\n", (long)GvGP(sv));
	PerlIO_printf(PerlIO_stderr(), "    SV = 0x%lx\n", (long)GvSV(sv));
	PerlIO_printf(PerlIO_stderr(), "    REFCNT = %ld\n", (long)GvREFCNT(sv));
	PerlIO_printf(PerlIO_stderr(), "    IO = 0x%lx\n", (long)GvIOp(sv));
	PerlIO_printf(PerlIO_stderr(), "    FORM = 0x%lx\n", (long)GvFORM(sv));
	PerlIO_printf(PerlIO_stderr(), "    AV = 0x%lx\n", (long)GvAV(sv));
	PerlIO_printf(PerlIO_stderr(), "    HV = 0x%lx\n", (long)GvHV(sv));
	PerlIO_printf(PerlIO_stderr(), "    CV = 0x%lx\n", (long)GvCV(sv));
	PerlIO_printf(PerlIO_stderr(), "    CVGEN = 0x%lx\n", (long)GvCVGEN(sv));
	PerlIO_printf(PerlIO_stderr(), "    LASTEXPR = %ld\n", (long)GvLASTEXPR(sv));
	PerlIO_printf(PerlIO_stderr(), "    LINE = %ld\n", (long)GvLINE(sv));
	PerlIO_printf(PerlIO_stderr(), "    FLAGS = 0x%x\n", (int)GvFLAGS(sv));
	fprintg(PerlIO_stderr(), "    EGV", GvEGV(sv));
	break;
    case SVt_PVIO:
	PerlIO_printf(PerlIO_stderr(), "  IFP = 0x%lx\n", (long)IoIFP(sv));
	PerlIO_printf(PerlIO_stderr(), "  OFP = 0x%lx\n", (long)IoOFP(sv));
	PerlIO_printf(PerlIO_stderr(), "  DIRP = 0x%lx\n", (long)IoDIRP(sv));
	PerlIO_printf(PerlIO_stderr(), "  LINES = %ld\n", (long)IoLINES(sv));
	PerlIO_printf(PerlIO_stderr(), "  PAGE = %ld\n", (long)IoPAGE(sv));
	PerlIO_printf(PerlIO_stderr(), "  PAGE_LEN = %ld\n", (long)IoPAGE_LEN(sv));
	PerlIO_printf(PerlIO_stderr(), "  LINES_LEFT = %ld\n", (long)IoLINES_LEFT(sv));
	PerlIO_printf(PerlIO_stderr(), "  TOP_NAME = \"%s\"\n", IoTOP_NAME(sv));
	fprintg(PerlIO_stderr(), "  TOP_GV", IoTOP_GV(sv));
	PerlIO_printf(PerlIO_stderr(), "  FMT_NAME = \"%s\"\n", IoFMT_NAME(sv));
	fprintg(PerlIO_stderr(), "  FMT_GV", IoFMT_GV(sv));
	PerlIO_printf(PerlIO_stderr(), "  BOTTOM_NAME = \"%s\"\n", IoBOTTOM_NAME(sv));
	fprintg(PerlIO_stderr(), "  BOTTOM_GV", IoBOTTOM_GV(sv));
	PerlIO_printf(PerlIO_stderr(), "  SUBPROCESS = %ld\n", (long)IoSUBPROCESS(sv));
	PerlIO_printf(PerlIO_stderr(), "  TYPE = %c\n", IoTYPE(sv));
	PerlIO_printf(PerlIO_stderr(), "  FLAGS = 0x%lx\n", (long)IoFLAGS(sv));
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
		fprintgg(PerlIO_stderr(), "GVGV::GV", CvGV(sv));
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
			    Dump(pad[j],4);
			    dumpit = 1;
			}
			/* else if (SvPOK(pad[j]) && SvPVX(pad[j])) { */
			else if (SvTYPE(pad[j]) >= SVt_PVAV) {
			    if (!SvPADMY(pad[j])) {
				levelref++;
				Dump(pad[j],4);
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
		    if (dumpit) Dump((SV*)cv,2);
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
