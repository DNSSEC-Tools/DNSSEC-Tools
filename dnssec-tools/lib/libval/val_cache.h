/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 
#ifndef RES_CACHE_H
#define RES_CACHE_H

void stow_zone_info(struct rrset_rec *new_info);
void stow_key_info(struct rrset_rec *new_info);
void stow_ds_info(struct rrset_rec *new_info);
void stow_answer(struct rrset_rec *new_info);
struct rrset_rec* get_cached_zones();
struct rrset_rec* get_cached_keys();
struct rrset_rec* get_cached_ds();
struct rrset_rec* get_cached_answers();
void free_validator_cache();

#endif
