/**
 * @file xml_output.cpp
 * utility routines for writing XML
 *
 * @remark Copyright 2006 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Dave Nomura
 */

#include <sstream>
#include <iostream>

#include "xml_output.h"

using namespace std;

string const xml_tag_map[] = {
	"NONE",
	"id",
	"profile",
		"processor",
		"cputype",
		"title",
		"schemaversion",
		"mhz",
	"setup",
	"timersetup",
		"rtcinterrupts",
	"eventsetup",
		"eventname",
		"unitmask",
		"setupcount",
		"separatedcpus",
	"options",
		"session", "debuginfo", "details", "excludedependent", "excludesymbols",
		"imagepath", "includesymbols", "merge",
	"classes",
	"class",
		"cpu",
		"event",
		"mask",
	"process",
		"pid",
	"thread",
		"tid",
	"binary",
	"module",
		"name",
	"callers",
	"callees",
	"symbol",
		"idref",
		"self",
		"detaillo",
		"detailhi",
	"symboltable",
	"symboldata",
		"startingaddr",
		"file",
		"line",
		"codelength",
	"summarydata",
	"sampledata",
	"count",
	"detailtable",
	"symboldetails",
	"detaildata",
		"vmaoffset",
	"bytestable",
	"bytes"
};


string tag_name(tag_t tag)
{
	return xml_tag_map[tag];
}


string open_element(tag_t tag, bool with_attrs)
{
	ostringstream out;

	out << "<" << tag_name(tag);
	if (with_attrs)
		out << " ";
	else
		out << ">" << endl;
	return out.str();
}


string close_element(tag_t tag, bool has_nested)
{
	ostringstream out;

	if (tag == NONE)
		out << (has_nested ? ">" : "/>");
	else
		out << "</" << tag_name(tag) << ">";
	out << endl;
	return out.str();
}


string init_attr(tag_t attr, size_t value)
{
	ostringstream out;

	out << " " << tag_name(attr) << "=\"" << value << "\"";
	return out.str();
}


string init_attr(tag_t attr, double value)
{
	ostringstream out;

	out << " " << tag_name(attr) << "=\"" << value << "\"";
	return out.str();
}


static string quote(string const & str)
{
	ostringstream out;

	string const quoted_chars("&<>\"");
	string::size_type pos = 0;
	string::size_type start = 0;
	string::size_type remain = str.size();

	
	out << "\"";

	while ((pos = str.find_first_of(quoted_chars, start)) != string::npos) {
		// output everything up to quoted char
		out << str.substr(start, pos-start);
		remain -= pos-start+1;
		start = pos + 1;

		// output replacement for quoted char
		switch (str[pos]) {
		case '&': out << "&amp;"; break;
		case '<': out << "&lt;"; break;
		case '>': out << "&gt;"; break;
		case '"': out << "&quot;"; break;
		}
	}

	// output remaining non-quoted part
	out << str.substr(start, remain);

	out << "\"";
	return out.str();
}


string init_attr(tag_t attr, string const & str)
{
	ostringstream out;

	out << " " << tag_name(attr) << "=" << quote(str);
	return out.str();
}


