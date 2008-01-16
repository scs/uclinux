#include "xmame.h"
#include "devices.h"

struct rc_option joy_SDL_opts[] = {
   { NULL,		NULL,			rc_end,		NULL,
     NULL,		0,			0,		NULL,
     NULL }
};


#if defined SDL_JOYSTICK

#include <SDL.h>

void joy_SDL_init(void);
void joy_SDL_poll(void);

SDL_Joystick 	*joystick[JOY_MAX];

void joy_SDL_init (void)
{
	int i,j;
	int joy_n=0;    

	if(SDL_Init(SDL_INIT_JOYSTICK ) < 0)
		printf ("SDL: JoyStick init Error!! ");
	else 
		printf("SDL: joystick interface initialization...\n");

	joy_n=SDL_NumJoysticks();
	printf("SDL: %d joysticks found.\n", joy_n );
	if (joy_n > JOY_MAX)
		joy_n = JOY_MAX;

	for (i = 0; i < joy_n; i++)
	{
		printf("SDL: The names of the joysticks :  %s\n", SDL_JoystickName(i));
		joystick[i]=SDL_JoystickOpen(i);      
		if ( joystick[i] )
		{
			/* Set the file descriptor to a dummy value. */
			joy_data[i].fd = 1;
			joy_data[i].num_buttons = SDL_JoystickNumButtons(joystick[i]);
			joy_data[i].num_axes    = SDL_JoystickNumAxes(joystick[i])
								+ (SDL_JoystickNumHats (joystick[i]) * 2)
								+ (SDL_JoystickNumBalls (joystick[i]) * 2);
			/* Each Hat Switch and Trackball is two dimensions */
			
			if (joy_data[i].num_buttons > JOY_BUTTONS)
				joy_data[i].num_buttons = JOY_BUTTONS;
			if (joy_data[i].num_axes > JOY_AXES)
				joy_data[i].num_axes = JOY_AXES;

			for (j=0; j<joy_data[i].num_axes; j++)
			{
				joy_data[i].axis[j].min = -32768;
				joy_data[i].axis[j].max =  32768;
				joy_data[i].axis[j].mid = 0;
			}
		}
		else
			printf("SDL:  the joystick init FAIL!!\n");

	}

	joy_poll_func = joy_SDL_poll;
}


void joy_SDL_poll (void)
{
#ifdef SDL_JOYSTICK
	int i,j,k;

	SDL_JoystickUpdate();

	for (i = 0; i < JOY_MAX; i++)
	{
		if (joy_data[i].fd)
		{
			k = 0; /* Count of total axes, including hats and balls */
			for (j=0; j<SDL_JoystickNumAxes(joystick[i]); j++)
			{
				if (k >= joy_data[i].num_axes)
					break;
				joy_data[i].axis[j].val= SDL_JoystickGetAxis(joystick[i], j);
				k++;
			}
			for (j=0; j<SDL_JoystickNumHats(joystick[i]);j++)
			{
				if (k +1 >= joy_data[i].num_axes)
					break;
				switch (SDL_JoystickGetHat (joystick[i], j)) 
				{
					case SDL_HAT_UP:
						joy_data[i].axis[k].val = joy_data[i].axis[k].mid;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].min;
						break;
					case SDL_HAT_RIGHT:
						joy_data[i].axis[k].val = joy_data[i].axis[k].max;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].mid;
						break;
					case SDL_HAT_DOWN:
						joy_data[i].axis[k].val = joy_data[i].axis[k].mid;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].max;
						break;
					case SDL_HAT_LEFT:
						joy_data[i].axis[k].val = joy_data[i].axis[k].min;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].mid;
						break;
					case SDL_HAT_RIGHTUP:
						joy_data[i].axis[k].val = joy_data[i].axis[k].max;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].min;
						break;
					case SDL_HAT_RIGHTDOWN:
						joy_data[i].axis[k].val = joy_data[i].axis[k].max;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].max;
						break;
					case SDL_HAT_LEFTUP:
						joy_data[i].axis[k].val = joy_data[i].axis[k].min;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].min;
						break;
					case SDL_HAT_LEFTDOWN:
						joy_data[i].axis[k].val = joy_data[i].axis[k].min;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].max;
						break;
					case SDL_HAT_CENTERED:
					default:
						joy_data[i].axis[k].val = joy_data[i].axis[k].mid;
						joy_data[i].axis[k+1].val = joy_data[i].axis[k+1].mid;
						break;
				}
				k += 2;
			}
			
			for (j=0; j<SDL_JoystickNumBalls(joystick[i]);j++)
			{
				if (k +1 >= joy_data[i].num_axes)
					break;
				SDL_JoystickGetBall (joystick[i], j, &joy_data[i].axis[k].val, &joy_data[i].axis[k+1].val);
				k += 2;
			}
			
			for (j=0; j<joy_data[i].num_buttons; j++)
				joy_data[i].buttons[j] = SDL_JoystickGetButton(joystick[i], j);
		}
	}
#endif
}

#endif
