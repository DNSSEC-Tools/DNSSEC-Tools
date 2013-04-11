165a166,173
> /*
>  * Variables used in modifications for the Owl Monitoring System.
>  *
>  *	owl_display	If set on, then the Services display will not show
>  *			the Last Check, Duration, and Attempt columns.
>  */
> int owl_display = 0;
> 
811a820,829
> 		else if(!strcmp(variables[x], "owl")) {
> 			x++;
> 			if(variables[x] == NULL) {
> 				error = TRUE;
> 				break;
> 				}
> 			if(!strcmp(variables[x], "display")) {
> 				owl_display = 1;
> 				}
> 			}
1473a1492,1493
>     if(owl_display == 0)
>     {
1478a1499
>     }
1888a1910,1912
> 
> 		    if(owl_display == 0)
> 		    {
1891a1916,1917
> 		    }
> 
