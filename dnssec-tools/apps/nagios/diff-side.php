85a86,117
> <!---------------------------------------------------------------------------->
> 
> <!--- Copyright 2013 SPARTA, Inc.  All rights reserved.			--->
> <!--- See the COPYING file distributed with this software for details.	--->
> 
> <div class="navsection">
> <div class="navsectiontitle">DNSEC Rollover Phases</div>
> <div class="navsectionlinks">
> 
> <dtnagios style="font-size: 8pt;">            
> <b>KSK Rollover Phases</b>:
> <p>KSK Phase 1 - wait for cache data to expire
> <p>KSK Phase 2 - generate a new (published) KSK and load zone
> <p>KSK Phase 3 - wait for the old DNSKEY RRset to expire from caches
> <p>KSK Phase 4 - transfer new keyset to the parent
> <p>KSK Phase 5 - wait for parent to publish DS record
> <p>KSK Phase 6 - wait for cache data to expire
> <p>KSK Phase 7 - roll the KSKs and load the zone
> </p>      
> 
> <dtnagios style="font-size: 8pt;">            
> <b>ZSK Rollover Phases</b>:
> <p>ZSK Phase 1 - wait for old zone data to expire from caches
> <p>ZSK Phase 2 - sign the zone with the KSK and Published ZSK
> <p>ZSK Phase 3 - wait for old zone data to expire from caches
> <p>ZSK Phase 4 - sign the zone with new Current ZSK
> </p>      
> 
> </dtnagios>
> </div>
> 
> <!---------------------------------------------------------------------------->
