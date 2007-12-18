#include "mpc2x.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fstream>
#include "SDL.h"
#include "SDL_image.h"
#include "SDL_ttf.h"

SDL_Surface * screen;
TTF_Font * font;
mpc2x_config *config;
char *songname = (char *)malloc(100);
int scrollpos;

#include "libmpdclient.h"

mpd_Connection * conn;

mpd_Status * status;

void updateSongTitle(void);

void config_parse_line(mpc2x_config *_config, char *line, int line_number)
{
	char *key, *value;

	key = strtok(line,"=");
	value = strtok(NULL,"\n");

	if(key == NULL || value == NULL) {
		printf("Invalid line in configuration file at line: %d\n",line_number);
		return;
	}
	if(strcmp(key, "mpd_hostname") == 0) {
		_config->mpd_hostname = strdup(value);
	}
	else if(strcmp(key, "mpd_hostport") == 0) {
		_config->mpd_hostport = atoi(value);
	}
	else if(strcmp(key, "mpd_timeout") == 0) {
		_config->mpd_timeout = atoi(value);
	}
	else if(strcmp(key, "skin_path") == 0) {
		_config->skin_path = strdup(value);
	}
	else if(strcmp(key, "font_path") == 0) {
		free(_config->font_path);
		_config->font_path = strdup(value);
	}
}

mpc2x_config *config_file(char *configfilepath)
{
	// read file and put in config
	mpc2x_config *_config = (mpc2x_config*)malloc(sizeof(mpc2x_config));
	if(!_config)
		return NULL;
	
	FILE *fd;
	fd = fopen(configfilepath, "r");
	if(!fd) {
		printf("Could not read configuration file\n");
		return _config;
	}

	char *buffer = (char *)malloc(256);
	char t_buf[256];

	buffer[0] = '\0';

	while(fgets((char *)&t_buf, 256, fd)) {
		strcat(buffer, t_buf);
		buffer = (char *)realloc(buffer, strlen(buffer) + 256);
	}
	fclose(fd);
	
	char *lines[10];
	int pass = 0;
	char *delim = "\n";
	lines[pass] = strtok(buffer,delim);
	while (lines[pass] != NULL) {
		pass++;
		lines[pass] = strtok(NULL,delim);
	}
	free(buffer);
	pass = 0;
	while (lines[pass] != NULL) {
		config_parse_line(_config, lines[pass], pass + 1);
		pass++;
	}

	return _config;
}

void mpdConnect()
{
	char *hostname = strdup(config->mpd_hostname);
	int port = config->mpd_hostport;
	int timeout = config->mpd_timeout;

	conn = mpd_newConnection(hostname,port,timeout);

	if(conn->error) {
		strcpy(songname, conn->errorStr);
		scrollpos = 0;
		updateSongTitle();
		mpd_closeConnection(conn);
	}
}

void mpdDisconnect()
{
	mpd_closeConnection(conn);
}

void mpdGetSongTitle()
{
	mpd_InfoEntity * entity;

	mpd_sendCommandListOkBegin(conn);
	mpd_sendStatusCommand(conn);
	mpd_sendCurrentSongCommand(conn);
	mpd_sendCommandListEnd(conn);

		if((status = mpd_getStatus(conn))==NULL) {
			fprintf(stderr,"%s\n",conn->errorStr);
			mpd_closeConnection(conn);
		}
	songname = (char *)malloc(100);
	
		mpd_nextListOkCommand(conn);

		while((entity = mpd_getNextInfoEntity(conn))) {
			mpd_Song * song = entity->info.song;

			if(entity->type!=MPD_INFO_ENTITY_TYPE_SONG) {
				mpd_freeInfoEntity(entity);
				continue;
			}

			if(song->artist) {
				strcpy(songname, " [");
				strcat(songname, song->artist);
				strcat(songname, " - ");
			}
			if(song->album) {
				strcat(songname, song->album);
				strcat(songname, " - ");
			}
			if(song->title) {
				songname = strcat(songname, song->title);
				songname = strcat(songname, "] ");
			}
			mpd_freeInfoEntity(entity);
		}

		if(conn->error) {
			fprintf(stderr,"%s\n",conn->errorStr);
			mpd_closeConnection(conn);
		}

		mpd_finishCommand(conn);
		if(conn->error) {
			fprintf(stderr,"%s\n",conn->errorStr);
			mpd_closeConnection(conn);
		}
	
}

void shutdown()
{	
	// Release the memory allocated to screen
	SDL_FreeSurface(screen);

	free(songname);
	free(font);

	mpdDisconnect();

	#ifndef GP2X
		// if GP2X isnt defined (i.e. PC) close SDL 
		SDL_Quit();
	#endif

	#ifdef GP2X
		// if GP2X is defined return to menu
		chdir("/usr/gp2x");
		SDL_ShowCursor(SDL_DISABLE);
		execl("/usr/gp2x/gp2xmenu", "/usr/gp2x/gp2xmenu", NULL);
	#endif
}

void drawText(SDL_Surface* screen, char* string, int x, int y, int fR, int fG, int fB)
{
	SDL_Color foregroundColor = { fR, fG, fB };
	SDL_Surface* textSurface =  TTF_RenderText_Blended(font, string, foregroundColor);
	SDL_Rect textLocation = { x, y, 0, 0 };
	SDL_BlitSurface(textSurface, NULL, screen, &textLocation);
	SDL_FreeSurface(textSurface);
	SDL_Flip(screen);
}

void drawPicture(SDL_Surface* screen, char* filename, int x, int y)
{

	SDL_Surface *image;
	SDL_Surface *temp;

	char *filepath = (char *)malloc(100);
	strcpy(filepath, config->skin_path);
	strcat(filepath, filename);
	temp = IMG_Load(filepath);
	if (temp == NULL)
		printf("Error loading images for the GUI.\n");
	image = SDL_DisplayFormat(temp);
	SDL_FreeSurface(temp);
	SDL_Rect src, dest;
	src.x = 0;
	src.y = 0;
	src.w = image->w;
	src.h = image->h;

	dest.x = x;
	dest.y = y;
	dest.w = image->w;
	dest.h = image->h;

	SDL_BlitSurface(image, &src, screen, &dest);
	SDL_FreeSurface(image);

}

void updateSongTitle()
{
	char *Text = songname;
	int Length = strlen(Text);
	int i;
	int k;
	char *Word;
	Word = (char *)malloc(400);

	int linelength = 28;

	i = scrollpos;
	if (i <= Length) {
		for(k = 0; k < linelength; k++)
		{
			if (i + k + 1 >= Length) {
				// start over again from beginning of string
				Word[k] = Text[(i + k) - Length + 1];
			}
			else {
				Word[k] = Text[i + k + 1];
			}
		}
		Word[k] = '\0';
		scrollpos++;

		drawPicture(screen,"songtitlebg.bmp",20,80);
		drawText(screen, Word, 20, 80, 255, 255, 255);
	}
	else {
		scrollpos = 0;
	}


}

void updateGUI()
{
	// update gui components:
	// + song played and total time
	// + song title scroll thing
	// + song position bar
	// + shuffle state
	// + repeat state
	// + volume

	// song title scroll thing
	updateSongTitle();

	if (status == NULL)
		return;

	char *timeline = (char*)malloc(32);
	sprintf(timeline,"%02i:%02i:%02i/%02i:%02i:%02i",status->elapsedTime/3600,status->elapsedTime/60,status->elapsedTime%60,status->totalTime/3600,status->totalTime/60,status->totalTime%60);
	drawPicture(screen,"songtimebg.bmp",80,20);
	drawText(screen, timeline, 80, 20, 255, 255, 255);

	char *infoline = (char*)malloc(32);
	sprintf(infoline, "%d Kbps/%d kHz", status->bitRate, status->sampleRate);
	drawPicture(screen,"songinfobg.bmp",80,40);
	drawText(screen, infoline, 80, 40, 255, 255, 255);

	float perc = status->elapsedTime<status->totalTime ?100.0*status->elapsedTime/status->totalTime :100.0;
	drawPicture(screen,"songposbg.bmp",20,120);
	drawPicture(screen,"cursor.bmp",(int)(20 + (perc * 3)),120);

	if (status->random == 0) {
		drawPicture(screen,"shuffle_false.bmp",20,160);
	}
	else {
		drawPicture(screen,"shuffle_true.bmp",20,160);
	}
	
	if (status->repeat == 0) {
		drawPicture(screen,"repeat_false.bmp",160,160);
	}
	else {
		drawPicture(screen,"repeat_true.bmp",160,160);
	}

	drawPicture(screen,"volumebg.bmp",200,200);
	drawPicture(screen,"cursor.bmp",200 + status->volume,200);
}

void buildGUI()
{
	drawPicture(screen,"background.bmp",0,0);
	
	SDL_Flip(screen);
	
	drawPicture(screen,"songposbg.bmp",20,120);
	drawPicture(screen,"volumebg.bmp",200,200);

	drawText(screen, "Shuffle", 60, 160, 255, 255, 255);
	drawText(screen, "Repeat", 200, 160, 255, 255, 255);

	drawText(screen, "[ |< ]", 20, 200, 255, 255, 255);
	drawText(screen, "[>/||]", 80, 200, 255, 255, 255);
	drawText(screen, "[ >| ]", 140, 200, 255, 255, 255);

	SDL_Flip(screen);
}



int main(int argc, char **argv)
{
	char *configfilename = "/etc/mpc2x.conf";
	config = config_file(configfilename);
	
	bool quit = false;

	// Init SDL
	SDL_Init(SDL_INIT_JOYSTICK | SDL_INIT_VIDEO | SDL_INIT_TIMER);
	// Prepare screen for GP2X
	screen = SDL_SetVideoMode( WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_DEPTH, SDL_SWSURFACE);
	if(!screen) {
		printf("SDL_SetVideoMode screen not initialised.\n");
		shutdown();
	}
	// Set window title, which we don't need on gp2x
	SDL_WM_SetCaption(WINDOW_TITLE, 0 );
	// Disable mouse cursus
	SDL_ShowCursor(SDL_DISABLE);

	// initialise the font stuff
	TTF_Init();

	// load the ttf font to be used
	char *fontpath = (char*) malloc(100);
	strcpy(fontpath,config->skin_path); // assume the font is in the skin path, should do this other way!
	strcat(fontpath,config->font_path);
	font = TTF_OpenFont(fontpath, 16);

	// Initialize the joystick
	SDL_JoystickOpen(0);

	songname = "........Not connected or no song playing at the moment...........";
	scrollpos = 0;
	mpdConnect();
	buildGUI();
	updateGUI();
	
	#define SONGTITLEINTERVAL 10
	int interval = 0;

	while (!quit)
	{
		SDL_Delay(100);
		interval++;
		if (interval == SONGTITLEINTERVAL) {
			mpdGetSongTitle();
			interval = 0;
			}

		updateGUI();
		
		SDL_Event event;
		while( SDL_PollEvent( &event ) )
		{
			switch( event.type )
			{
				case SDL_JOYBUTTONUP:
					drawText(screen, "[ |< ]", 20, 200, 255, 255, 255);
					drawText(screen, "[>/||]", 80, 200, 255, 255, 255);
					drawText(screen, "[ >| ]", 140, 200, 255, 255, 255);
					SDL_Flip(screen);
					break;
				case SDL_JOYBUTTONDOWN:
					switch( event.jbutton.button )
					{
						case GP2X_BUTTON_VOLUP :
						// volume up
							mpd_sendSetvolCommand(conn, status->volume + 5);
							mpd_finishCommand(conn);
							break;
						case GP2X_BUTTON_VOLDOWN :
						// volume down
							mpd_sendSetvolCommand(conn, status->volume - 5);
							mpd_finishCommand(conn);
							break;
						case GP2X_BUTTON_A :
						// play/pause
							if(status->state == MPD_STATUS_STATE_PLAY)
							{
								mpd_sendPauseCommand(conn,1);
							}
							else if(status->state == MPD_STATUS_STATE_PAUSE || status->state == MPD_STATUS_STATE_STOP)
							{
								mpd_sendPauseCommand(conn,0);
							}
							mpd_finishCommand(conn);
							drawText(screen, "[>/||]", 80, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case GP2X_BUTTON_R :
						// next track
							mpd_sendNextCommand(conn);
							mpd_finishCommand(conn);
							drawText(screen, "[ >| ]", 140, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case GP2X_BUTTON_L :
						// prev track
							mpd_sendPrevCommand(conn);
							mpd_finishCommand(conn);
							drawText(screen, "[ |< ]", 20, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case GP2X_BUTTON_Y :
						// shuffle toggle
							if(status->random == 0)
							{
								mpd_sendRandomCommand(conn,1);
							}
							else
							{
								mpd_sendRandomCommand(conn,0);
							}
							mpd_finishCommand(conn);
							break;
						case GP2X_BUTTON_B :
						// repeat toggle
							if(status->repeat == 0)
							{
								mpd_sendRepeatCommand(conn,1);
							}
							else
							{
								mpd_sendRepeatCommand(conn,0);
							}
							mpd_finishCommand(conn);
							break;
						case GP2X_BUTTON_START :
						// quit
						 	quit=true;
							break;
						case GP2X_BUTTON_SELECT :
						// cycle other screens
							break;
						case GP2X_BUTTON_RIGHT :
						// forward in song
							mpd_sendSeekCommand(conn, status->song, status->elapsedTime + 5);
							mpd_finishCommand(conn);
							break;
						case GP2X_BUTTON_LEFT :
						// backward in song
							mpd_sendSeekCommand(conn, status->song, status->elapsedTime - 5);
							mpd_finishCommand(conn);
							break;
						default:
							break;
					}
					break;
				case SDL_KEYDOWN:
					switch( event.key.keysym.sym )
					{
						case SDLK_KP_PLUS :
						// volume up
							mpd_sendSetvolCommand(conn, status->volume + 5);
							mpd_finishCommand(conn);
							break;
						case SDLK_KP_MINUS :
						// volume down
							mpd_sendSetvolCommand(conn, status->volume - 5);
							mpd_finishCommand(conn);
							break;
						case SDLK_SPACE :
						// play/pause
							if(status->state == MPD_STATUS_STATE_PLAY)
							{
								mpd_sendPauseCommand(conn,1);
							}
							else if(status->state == MPD_STATUS_STATE_PAUSE || status->state == MPD_STATUS_STATE_STOP)
							{
								mpd_sendPauseCommand(conn,0);
							}
							mpd_finishCommand(conn);
							drawText(screen, "[>/||]", 80, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case SDLK_RIGHT	:
						// next track
							mpd_sendNextCommand(conn);
							mpd_finishCommand(conn);
							drawText(screen, "[ >| ]", 140, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case SDLK_LEFT :
						// prev track
							mpd_sendPrevCommand(conn);
							mpd_finishCommand(conn);
							drawText(screen, "[ |< ]", 20, 200, 255, 255, 0);
							SDL_Flip(screen);
							break;
						case SDLK_s :
						// shuffle toggle
							if(status->random == 0)
							{
								mpd_sendRandomCommand(conn,1);
							}
							else
							{
								mpd_sendRandomCommand(conn,0);
							}
							mpd_finishCommand(conn);
							break;
						case SDLK_r :
						// repeat toggle
							if(status->repeat == 0)
							{
								mpd_sendRepeatCommand(conn,1);
							}
							else
							{
								mpd_sendRepeatCommand(conn,0);
							}
							mpd_finishCommand(conn);
							break;
						case SDLK_ESCAPE :
						// quit
						 	quit=true;
							break;
						case SDLK_TAB :
						// cycle other screens
							break;
						case SDLK_UP :
						// forward in song
							mpd_sendSeekCommand(conn, status->song, status->elapsedTime + 5);
							mpd_finishCommand(conn);
							break;
						case SDLK_DOWN :
						// backward in song
							mpd_sendSeekCommand(conn, status->song, status->elapsedTime - 5);
							mpd_finishCommand(conn);
							break;
						default:
							break;
					}
					break;
			}
		}
	}

	shutdown();
	return 0;
}
