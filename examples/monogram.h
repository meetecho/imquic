/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * monogram bitmap font (https://datagoblin.itch.io/monogram), converted
 * to a C header for use in the demos without the need for external files
 *
 */

#ifndef MONOGRAM_H
#define MONOGRAM_H

#include <glib.h>
#include <SDL2/SDL.h>

/* Font details */
#define MONOGRAM_FONT_WIDTH		96
#define MONOGRAM_FONT_HEIGHT	96
#define MONOGRAM_GLYPH_WIDTH	6
#define MONOGRAM_GLYPH_HEIGHT	12

/* Helper to load the embedded font */
int monogram_load_font(SDL_Renderer *renderer);
/* Helper to get rid of embedded font */
void monogram_unload_font(void);

/* Helper to write text */
int monogram_write(SDL_Renderer *renderer, const char *text,
	int x, int y, float scale, int screen_w, int screen_h);

#endif
