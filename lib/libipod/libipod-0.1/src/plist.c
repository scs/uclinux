/*
 * plist.c
 *
 * Duane Maxwell
 * (c) Linspire, Inc 2005
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifdef PLIST
#include "plist.h"
#include <stdio.h>
#include <expat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static plist_item *plist_item_new(int type) {
	plist_item *item = (plist_item *)malloc(sizeof(plist_item));
	item->p_type = type;
	return item;
}

int plist_item_type(plist_item *p) {
	return p->p_type;
}

int plist_item_is_type(plist_item *p,int type) {
	return p->p_type==type;
}

plist_item *plist_item_from_integer(int i) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_INTEGER);
	item->u.p_integer = i;
	return item;
}

plist_item *plist_item_from_real(double f) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_REAL);
	item->u.p_real = f;
	return item;
}

plist_item *plist_item_from_string(char *s) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_STRING);
	item->u.p_string = (char *)malloc(strlen(s)+1);
	strcpy(item->u.p_string,s);
	return item;
}

plist_item *plist_item_from_boolean(int b) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_BOOLEAN);
	item->u.p_boolean = (b!=0);
	return item;
}


plist_item *plist_item_from_date(time_t t) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_DATE);
	item->u.p_date = t;
	return item;
}

plist_item *plist_item_from_data(void *bytes,size_t len) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_DATA);
	item->u.p_data.p_data_length = len;
	item->u.p_data.p_data = (void *)malloc(len);
	if (bytes && len>0)
		memcpy(item->u.p_data.p_data,bytes,len);
	return item;
}


plist_item *plist_item_new_array(void) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_ARRAY);
	item->u.p_array.p_array_length = 0;
	item->u.p_array.p_array_items = (plist_item **)malloc(0);
	return item;
}

plist_item *plist_item_new_dict(void) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_DICT);
	item->u.p_dict.p_dict_length = 0;
	item->u.p_dict.p_dict_items = (plist_dict_element *)malloc(0);
	return item;
}

plist_item *plist_item_new_plist(void) {
	plist_item *item = plist_item_new(PLIST_ITEM_TYPE_PLIST);
	item->u.p_child = 0;
	return item;
}

void plist_item_free(plist_item *p) {
	size_t count;
	plist_item **a_item;
	plist_dict_element *d_item;
	//printf("freeing %lx of type %d\n",p,plist_item_type(p));
	if (p) {
		switch (p->p_type) {
			case PLIST_ITEM_TYPE_INTEGER:
			case PLIST_ITEM_TYPE_REAL:
			case PLIST_ITEM_TYPE_BOOLEAN:
			case PLIST_ITEM_TYPE_DATE:
				break;
			case PLIST_ITEM_TYPE_STRING:
				free(p->u.p_string);
				break;
			case PLIST_ITEM_TYPE_DATA:
				free(p->u.p_data.p_data);
				break;
			case PLIST_ITEM_TYPE_ARRAY:
				count = plist_item_array_length(p);
				a_item = p->u.p_array.p_array_items;
				while (count--) {
					plist_item_free(*a_item);
					a_item++;
				}
				break;
			case PLIST_ITEM_TYPE_DICT:
				count = plist_item_dict_length(p);
				d_item = p->u.p_dict.p_dict_items;
				while (count--) {
					free(d_item->p_key);
					plist_item_free(d_item->p_value);
					d_item++;
				}
				break;
			case PLIST_ITEM_TYPE_PLIST:
				plist_item_free(p->u.p_child);
				break;
		}
		free(p);
	}
}

static void indent(int indention) {
	while (indention--)
		printf("  ");
}

static void dumpEncodedString(char *s) {
	char ch;
	while (ch=*s++) {
		switch (ch) {
			case '\'': printf("&apos;"); break;
			case '"' : printf("&quot;"); break;
			case '&' : printf("&amp;"); break;
			case '<' : printf("&lt;"); break;
			case '>' : printf("&gt;"); break;
			default:   printf("%c",ch); break;
		}
	}
}

static void plist_dump1(plist_item *p,int indention) {
	indent(indention);
	switch (plist_item_type(p)) {
		case PLIST_ITEM_TYPE_INTEGER:
			printf("<integer>%d</integer>",plist_item_integer_value(p));
			break;
		case PLIST_ITEM_TYPE_REAL:
			printf("<real>%g</real>",plist_item_real_value(p));
			break;
		case PLIST_ITEM_TYPE_STRING:
			printf("<string>");
			dumpEncodedString(plist_item_string_value(p));
			printf("</string>");
			break;
		case PLIST_ITEM_TYPE_BOOLEAN:
			printf(plist_item_boolean_value(p)?"<true/>":"<false/>");
			break;
		case PLIST_ITEM_TYPE_DATE:
			{
				time_t t = plist_item_date_value(p);
				char s[255];
				strftime(s,255,"%Y-%m-%dT%H:%M:%SZ",gmtime(&t));
				printf("<date>%s</date>",s);
			}
			break;
		case PLIST_ITEM_TYPE_ARRAY:
			printf("<array>\n");
			{
				size_t  count = plist_item_array_length(p);
				size_t i = 0;
				for (i=0;i<count;i++) {
					plist_item *e = plist_item_array_at_index(p,i);
					if (e) plist_dump1(e,indention+1);
				}
			}
			indent(indention);
			printf("</array>");
			break;
		case PLIST_ITEM_TYPE_DICT:
			printf("<dict>\n");
			{
				size_t  count = plist_item_dict_length(p);
				size_t i;
				for (i=0;i<count;i++) {
					char *key = plist_item_dict_key_at_index(p,i);
					plist_item *value = plist_item_dict_at_key(p,key);
					if (value) {
						indent(indention+1);
						printf("<key>");
						dumpEncodedString(key);
						printf("</key>\n");
						plist_dump1(value,indention+1);
					}
				}
			}
			indent(indention);
			printf("</dict>");
			break;
		case PLIST_ITEM_TYPE_DATA: {
			size_t len,i;
			char *data = (char *) plist_item_data_value(p,&len);
			printf("<data>\n");
			for (i=0;i<len;i++)
				printf("%c",data[i]);
			printf("</data>");
			}
			break;
		case PLIST_ITEM_TYPE_PLIST: {
			plist_item *child;
			printf("<plist>\n");
			child = plist_item_plist_value(p);
			if (child) plist_dump1(child,indention+1);
			printf("</plist>");
			}
			break;
		default:
			printf("Unknown type %d\n",plist_item_type(p));
			exit(1);
	}
	printf("\n");
}

 
char *plist_string_item(plist_item *p,char *key,char *if_missing) {
	plist_item *pp =  plist_item_dict_at_key (p,key);
	if (pp && plist_item_type(pp)==PLIST_ITEM_TYPE_STRING)
		return plist_item_string_value(pp);
	return if_missing;
}
  
int plist_bool_item(plist_item *p,char *key,int if_missing) {
	plist_item *pp =  plist_item_dict_at_key (p,key);
	if (pp && plist_item_type(pp)==PLIST_ITEM_TYPE_BOOLEAN)
		if (pp && plist_item_boolean_value(pp)!=0)
			return 1;
		else
			return 0;
	return if_missing;
}
  
time_t plist_date_item(plist_item *p,char *key,time_t if_missing) {
	plist_item *pp =  plist_item_dict_at_key (p,key);
	if (pp && plist_item_type(pp)==PLIST_ITEM_TYPE_DATE)
		return plist_item_date_value(pp);
	return if_missing;
}

int plist_integer_item(plist_item *p,char *key,int if_missing) {
	plist_item *pp =  plist_item_dict_at_key (p,key);
	if (pp && plist_item_type(pp)==PLIST_ITEM_TYPE_INTEGER)
		return plist_item_integer_value(pp);
	return if_missing;
}

//-----------------------------------------


void plist_dump(plist_item *p) {
	plist_dump1(p,0);
}

int plist_item_integer_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_INTEGER))
		return p->u.p_integer;
	return 0;
}

double plist_item_real_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_REAL))
		return p->u.p_real;
	return 0;
}

char *plist_item_string_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_STRING))
		return p->u.p_string;
	return 0;
}

int plist_item_boolean_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_BOOLEAN))
		return p->u.p_boolean;
	return 0;
}

time_t plist_item_date_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_DATE))
		return p->u.p_date;
	return 0;
}

void *plist_item_data_value(plist_item *p,size_t *len) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_DATA)) {
		*len = p->u.p_data.p_data_length;
		return p->u.p_data.p_data;
	}
	return 0;
}

plist_item *plist_item_plist_value(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_PLIST))
		return p->u.p_child;
	return 0;
}


size_t plist_item_array_length(plist_item *p) {
	if (plist_item_is_type(p,PLIST_ITEM_TYPE_ARRAY))
		return p->u.p_array.p_array_length;
	return 0;
}

plist_item *plist_item_array_at_index(plist_item *array,int i) {
	if (plist_item_is_type(array,PLIST_ITEM_TYPE_ARRAY)) {
		size_t len = plist_item_array_length(array);
		if (i>=0 && i<(int)len) {
			return array->u.p_array.p_array_items[i];
		}
	}
	return 0;
}

plist_item *plist_item_array_at_index_put(plist_item *array,int i,plist_item *value) {
	if (plist_item_is_type(array,PLIST_ITEM_TYPE_ARRAY)) {
		size_t len = plist_item_array_length(array);
		if (i>=0 && i<(int)len) {
			plist_item_free(array->u.p_array.p_array_items[i]);
			array->u.p_array.p_array_items[i] = value;
		}
	}
	return array;
}

plist_item *plist_item_array_append(plist_item *array,plist_item *p) {
	if (plist_item_is_type(array,PLIST_ITEM_TYPE_ARRAY)) {
		size_t len = plist_item_array_length(array)+1;
		plist_array_type *a = &array->u.p_array;
		a->p_array_length = len;
		a->p_array_items = (plist_item **)realloc(a->p_array_items,len*sizeof(plist_item *));
		a->p_array_items[len-1] = p;
	}
	return array;
}

size_t plist_item_dict_length(plist_item *dict) {
	if (plist_item_is_type(dict,PLIST_ITEM_TYPE_DICT))
		return dict->u.p_dict.p_dict_length;
	return 0;
}

char *plist_item_dict_key_at_index(plist_item *dict,int i) {
	if (plist_item_is_type(dict,PLIST_ITEM_TYPE_DICT))
		return dict->u.p_dict.p_dict_items[i].p_key;
	return 0;
}

static plist_dict_element *plist_item_dict_element_for_key(plist_item *dict,char *key) {
	size_t len = plist_item_dict_length(dict);
	size_t i;
	plist_dict_element *elements = dict->u.p_dict.p_dict_items;
	for (i=0;i<len;i++) {
		plist_dict_element *element = &elements[i];
		if (strcmp(key,element->p_key)==0)
			return element;
	}
	return 0;
}

int plist_item_dict_has_key(plist_item *dict,char *key) {
	if (plist_item_is_type(dict,PLIST_ITEM_TYPE_DICT))
		return plist_item_dict_element_for_key(dict,key)!=0;
	return 0;
}

plist_item *plist_item_dict_at_key(plist_item *dict,char *key) {
	if (plist_item_is_type(dict,PLIST_ITEM_TYPE_DICT)) {
		plist_dict_element *element = plist_item_dict_element_for_key(dict,key);
		return element?element->p_value:0;
	}
	return 0;
}

plist_item *plist_item_dict_at_key_put(plist_item *dict,char *key,plist_item *value) {
	if (plist_item_is_type(dict,PLIST_ITEM_TYPE_DICT)) {
		plist_dict_element *element = plist_item_dict_element_for_key(dict,key);
		if (element) { // replace existing value
			plist_item_free(element->p_value);
			element->p_value = value;
		} else { // append new key/value pair
			plist_dict_element element;
			plist_dict_type *d = &dict->u.p_dict;
			element.p_key = (char *)malloc(strlen(key)+1);
			strcpy(element.p_key,key);
			element.p_value = value;
			d->p_dict_length++;
			d->p_dict_items = (plist_dict_element *)realloc(d->p_dict_items,d->p_dict_length*sizeof(plist_dict_element));
			d->p_dict_items[d->p_dict_length-1] = element;
		}
		return dict;
	}
	return 0;
}

plist_item *plist_item_plist_set_value(plist_item *plist,plist_item *value) {
	if (plist_item_is_type(plist,PLIST_ITEM_TYPE_PLIST)) {
		plist_item_free(plist->u.p_child);
		plist->u.p_child = value;
	}
	return plist;
}


typedef struct user_data {
	XML_Parser xml;
	char *s;
	char *key;
	plist_item *root;
	plist_item *current;
} user_data;

static char *plist_tag_names[] = {
	"<><>", // will never happen
	"integer",
	"real",
	"string",
	"true",
	"false",
	"date",
	"data",
	"array",
	"dict",
	"plist",
	"key",
	0
};

static int plist_item_type_from_name(const char *name) {
	char **names = plist_tag_names;
	int index = 0;
	while (*names) {
		if (strcmp(*names,name)==0) return index;
		index++; names++;
	}
	return 0;
}

static void addToAggregate(user_data *u,plist_item *p) {
	int type = plist_item_type(u->current);
	switch (type) {
		case PLIST_ITEM_TYPE_ARRAY:
			plist_item_array_append(u->current,p);
			break;
		case PLIST_ITEM_TYPE_DICT:
			plist_item_dict_at_key_put(u->current,u->key,p);
			break;
		case PLIST_ITEM_TYPE_PLIST:
			plist_item_plist_set_value(u->current,p);
			break;
		default:
			fprintf(stderr,"addToAggregate(): illegal aggregate %d\n",type);
	}
}

static void startElement(void *userData,const char *name,const char **attributes) {
	user_data *u = (user_data *)userData;
	int type;
	u->s = (char *)realloc(u->s,1); // kill any lingering text
	u->s[0] = 0;
	switch (type = plist_item_type_from_name(name)) {
		case PLIST_ITEM_TYPE_INTEGER:
		case PLIST_ITEM_TYPE_REAL:
		case PLIST_ITEM_TYPE_STRING:
		case PLIST_ITEM_TYPE_DATE:
		case PLIST_ITEM_TYPE_DATA:
			break;
		case PLIST_ITEM_TYPE_TRUE:
		case PLIST_ITEM_TYPE_FALSE:
			break;
		case PLIST_ITEM_TYPE_ARRAY: {
			plist_item *p = plist_item_new_array();
			addToAggregate(u,p);
			p->p_parent = u->current;
			u->current = p;
			}
			break;
		case PLIST_ITEM_TYPE_DICT: {
			plist_item *p = plist_item_new_dict();
			addToAggregate(u,p);
			p->p_parent = u->current;
			u->current = p;
			}
			break;
		case PLIST_ITEM_TYPE_KEY:
			break;
		case PLIST_ITEM_TYPE_PLIST:
			u->root = plist_item_new_plist();
			u->current = u->root;
			break;
		default:
			fprintf(stderr,"Unrecognized tag %s\n",name);
			exit(1);
	}
}

static void endElement(void *userData,const char *name) {
	user_data *u = (user_data *)userData;
	int type;
	switch (type=plist_item_type_from_name(name)) {
		case PLIST_ITEM_TYPE_INTEGER: {
			long i;
			sscanf(u->s,"%ld",&i);
			addToAggregate(u,plist_item_from_integer(i));
			}
			break;
		case PLIST_ITEM_TYPE_REAL: {
			double f;
			sscanf(u->s,"%lg",&f);
			addToAggregate(u,plist_item_from_real(f));
			}
			break;
		case PLIST_ITEM_TYPE_STRING: {
			addToAggregate(u,plist_item_from_string(u->s));
			}
			break;
		case PLIST_ITEM_TYPE_TRUE:
			addToAggregate(u,plist_item_from_boolean(1));
			break;
		case PLIST_ITEM_TYPE_FALSE:
			addToAggregate(u,plist_item_from_boolean(0));
			break;
		case PLIST_ITEM_TYPE_DATE: {
			struct tm t;
			strptime(u->s,"%Y-%m-%dT%H:%M:%SZ",&t);
			addToAggregate(u,plist_item_from_date(mktime(&t)));
			}
			break;
		case PLIST_ITEM_TYPE_DATA: {
			addToAggregate(u,plist_item_from_data(u->s,strlen(u->s)));
			}
			break;
		case PLIST_ITEM_TYPE_ARRAY:
			u->current = u->current->p_parent;
			break;
		case PLIST_ITEM_TYPE_DICT:
			u->current = u->current->p_parent;
			break;
		case PLIST_ITEM_TYPE_PLIST:
			u->current = u->current->p_parent;
			break;
		case PLIST_ITEM_TYPE_KEY:
			u->key = (char *)realloc(u->key,strlen(u->s)+1);
			strcpy(u->key,u->s);
			break;
	}
}

static void charHandler(void *userData,const char *s,int len) {
	user_data *u = (user_data *)userData;
	int oldlen = strlen(u->s);
	int newlen = oldlen+len;
	u->s = (char *)realloc(u->s,newlen+1);
	memcpy(&u->s[oldlen],s,len);
	u->s[newlen] = 0;
}

#define BUF_SIZE 2048

plist_item *plist_item_from_file(char *fileName) {
	FILE *f;
	int isFinal;
	user_data u;
	u.s = (char *)malloc(1);
	u.s[0] = 0;
	u.key = (char *)malloc(1);
	u.key[0] = 0;
	XML_Parser xml = XML_ParserCreate(NULL);
	u.xml = xml;
	XML_SetUserData(xml,&u);
	XML_SetElementHandler(xml,startElement,endElement);
	XML_SetCharacterDataHandler(xml,charHandler);
	f = fopen(fileName,"r");
	if (f) {
		char buffer[BUF_SIZE];
		int firstRun=1;
		do {
			int bytesRead = fread(buffer,1,BUF_SIZE,f);
			if(firstRun==1 && bytesRead==0) {
				XML_ParserFree(xml);
				free(u.root);
				return NULL;
			}
			else firstRun=0;
			isFinal = !(bytesRead==BUF_SIZE);
			XML_Parse(xml,buffer,bytesRead,isFinal);
		} while (!isFinal);
		fclose(f);
	}
	else {
		fprintf(stderr,"plist_item_from_file(): Couldn't open file %s\n",fileName);
		XML_ParserFree(xml);
		free(u.root);
		return NULL;
	}
	XML_ParserFree(xml);
	free(u.key);
	free(u.s);
	return u.root;
}

#endif
