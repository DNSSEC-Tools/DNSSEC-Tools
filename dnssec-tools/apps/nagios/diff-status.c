#
# Copyright 2011-2013 SPARTA, Inc.  All rights reserved.
# See the COPYING file distributed with this software for details.
#


80a81,85
> /*
>  * Defines used by the DNSSEC-Tools modifications.
>  */
> #define	ROLL_STATUS	"Zone Rollover"
> 
1253a1259
> 	char *dt_rollstatus="";			/* DNSSEC-Tools	*/
1521a1528
> 				dt_rollstatus = "PENDING";    /* DNSSEC_Tools */
1526a1534,1545
> 
> 				/* DNSSEC_Tools */
> 				if((strncmp(temp_status->plugin_output,"KSK Rollover",12) == 0) ||
> 				   (strncmp(temp_status->plugin_output,"ZSK Rollover",12) == 0))
> 				{
> 					dt_rollstatus = "ROLLING";
> 				}
> 				else
> 				{
> 					dt_rollstatus = "NORMAL";
> 				}
> 
1536a1556
> 				dt_rollstatus = "ATTENTION REQUIRED";    /* DNSSEC_Tools */
1546a1567
> 				dt_rollstatus = "UNKNOWN";    /* DNSSEC_Tools */
1556a1578
> 				dt_rollstatus = "ATTENTION REQUIRED";    /* DNSSEC_Tools */
1560d1581
< 
1786c1807,1815
< 			printf("<TD CLASS='status%s'>%s</TD>\n",status_class,status);
---
> 			if(strcmp(temp_status->description,ROLL_STATUS) != 0)
> 			{
> 				printf("<TD CLASS='status%s'>%s</TD>\n",status_class,status);
> 			}
> 			else
> 			{
>                         	/* DNSSEC_Tools */
> 				printf("<TD CLASS='status%s'>%s</TD>\n",status_class,dt_rollstatus);
> 			}
