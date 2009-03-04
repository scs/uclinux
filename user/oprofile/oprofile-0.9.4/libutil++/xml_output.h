/**
 * @file xml_output.h
 * utility routines for writing XML
 *
 * @remark Copyright 2006 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Dave Nomura
 */

#ifndef XML_OUTPUT_H
#define XML_OUTPUT_H

typedef enum {
	NONE=0, TABLE_ID, PROFILE,
	PROCESSOR, CPU_NAME, TITLE, SCHEMA_VERSION, MHZ,
	SETUP, 
	TIMER_SETUP, RTC_INTERRUPTS,
	EVENT_SETUP, EVENT_NAME, UNIT_MASK, SETUP_COUNT, SEPARATED_CPUS,
	OPTIONS, SESSION, DEBUG_INFO, DETAILS, EXCLUDE_DEPENDENT, EXCLUDE_SYMBOLS,
		IMAGE_PATH, INCLUDE_SYMBOLS, MERGE,
	CLASSES,
	CLASS,
		CPU_NUM,
		EVENT_NUM,
		EVENT_MASK,
	PROCESS, PROC_ID,
	THREAD, THREAD_ID,
	BINARY,
	MODULE, NAME,
	CALLERS, CALLEES,
	SYMBOL, ID_REF, SELFREF, DETAIL_LO, DETAIL_HI,
	SYMBOL_TABLE,
	SYMBOL_DATA, STARTING_ADDR,
		SOURCE_FILE, SOURCE_LINE, CODE_LENGTH,
	SUMMARY, SAMPLE,
	COUNT,
	DETAIL_TABLE, SYMBOL_DETAILS, DETAIL_DATA, VMA,
	BYTES_TABLE, BYTES} tag_t;

std::string tag_name(tag_t tag);
std::string open_element(tag_t tag, bool with_attrs = false);
std::string close_element(tag_t tag = NONE, bool has_nested = false);
std::string init_attr(tag_t attr, size_t value);
std::string init_attr(tag_t attr, double value);
std::string init_attr(tag_t attr, std::string const & str);

#endif /* !XML_OUTPUT_H */
