/*
 * sorted_list.h
 *
 *  Created on: Dec 4, 2012
 *      Author: dschmitt
 */

#ifndef SORTED_LIST_H_
#define SORTED_LIST_H_

#include <inttypes.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h> // for malloc and free

// Entries that are stored in a linked list
typedef struct list_entry list_entry_t;
struct list_entry
{
	list_entry_t* next;
	list_entry_t* prev;
	uint16_t value;
};

void set_min_value_and_max_value(uint16_t min_value_to_set, uint16_t max_value_to_set);
void push(list_entry_t** phead, list_entry_t* entry);
list_entry_t* front(list_entry_t** phead);
void pop_front(list_entry_t** phead);

#endif /* SORTED_LIST_H_ */
