/*
 * sorted_list.c
 *
 *  Created on: Dec 4, 2012
 *      Author: dschmitt
 */

#include "sorted_list.h"

uint16_t min_value;
uint16_t max_value;

// Set the range on the values to be added to this sorted linked list
void set_min_value_and_max_value(uint16_t min_value_to_set, uint16_t max_value_to_set)
{
	min_value = min_value_to_set;
	max_value = max_value_to_set;
}

// Push an already-malloc'd entry into the linked list.  Will automatically put it in the correct
//     order based on its value
void push(list_entry_t** phead, list_entry_t* entry)
{
	// Case there aren't any entries in the list already, so make
	//     the incoming entry the head
	if(!*phead)
	{
		(*phead) = entry;
		(*phead)->next = 0;
		(*phead)->prev = 0;
		return;
	}

	// Case the entry's value is outside the range supported, so we can't insert it in the linked list
	if(entry->value < min_value || entry->value > max_value)
		return;

	// Where the entry should be inserted
	uint16_t index = entry->value;
	list_entry_t* node = *phead;

	// Loop as long as there's another node to the right
	//     and the value of the current entry is less
	//     than your desired one
	while(node->next && (node->value < index))
		node = node->next;

	// Case we're short of our value and we've stopped looping
	//     which means we're at the end of the linked list
	if(node->value < entry->value)
	{
		// Insert after current node

		// Establish the new entry's links to his neighbors
		entry->next = node->next;
		entry->prev = node;

		// Establish his neighbors' links to him (if he even has neighbors)
		if(node->next)
			node->next->prev = entry;
		node->next = entry;
	}
	// Case we've landed on our value and we want to overwrite it
	else if(node->value == index)
	{
		// Overwrite current node

		// Establish the new entry's links to his neighbors
		entry->next = node->next;
		entry->prev = node->prev;

		// Establish his neighbors links to him (if he even has neighbors)
		if(node->prev)
			node->prev->next = entry;
		if(node->next)
			node->next->prev = entry;

		// Remove the old node from the linked list
		free(node);
	}
	// Case we've overshot our value by one
	else
	{
		// Insert before current node

		// Establish the new entry's links to his neighbors
		entry->next = node;
		entry->prev = node->prev;

		// Establish his neighbors links to him (if he even has neighbors)
		if(node->prev)
			node->prev->next = entry;
		node->prev = entry;
	}

	// Case we've set the entry at the head, so reset the head here too
	if((*phead) == node)
		(*phead) = entry;
}

// Get from front of linked list.  If there are no entries
//     return a NULL memory address.  This function neither malloc's
//     nor frees any memory.  The caller must call pop_front afterward
//     to actually remove the entry from the linked list
list_entry_t* front(list_entry_t** phead)
{
	// Case there aren't any entries in the linked list, so return NULL
	list_entry_t* head = *phead;
	if(!head)
		return 0;

	return head;
}

// Remove the entry at the head of the linked list and if this empties the list,
//     add a new entry at the head whose value is one greater than the one
//     removed.  This function does not free the memory
void pop_front(list_entry_t** phead)
{
	// Case the list is already empty, which shouldn't ever happen
	if(!*phead)
		return;

	uint16_t value_removed = (*phead)->value;

	// Move the head to be the next in line
	*phead = (*phead)->next;

	// Case there's already one next in line, so the list isn't empty now
	if(*phead)
		(*phead)->prev = 0;

	// Case the list is now empty, so create a new entry at the head with
	//     a value one greater than the one just removed
	else
	{
		(*phead) = malloc(sizeof(list_entry_t));
		(*phead)->value = ++value_removed;
		(*phead)->next = 0;
		(*phead)->prev = 0;
	}
}


