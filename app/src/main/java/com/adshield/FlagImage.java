package com.adshield;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;

/**
 * Turns a flag emoji into a flat, rounded-rectangle flag picture like VPN apps show, using
 * the phone's own emoji font (no download needed).
 */
final class FlagImage {
    private static final float WIDTH_DP = 38;
    private static final float HEIGHT_DP = 26;
    private static final float CORNER_DP = 5;
    // Trim this much off each edge to drop the emoji's waves, shading and outline.
    private static final float INSET_X = 0.06f;
    private static final float INSET_Y = 0.10f;

    /** Returns the flag picture, or null if the emoji can't be drawn as a flag. */
    static Bitmap render(Context context, String emoji) {
        if (emoji.isEmpty()) return null;
        Paint text = new Paint(Paint.ANTI_ALIAS_FLAG);
        text.setTextSize(256);
        Paint.FontMetrics fm = text.getFontMetrics();
        int w = (int) Math.ceil(text.measureText(emoji));
        int h = (int) Math.ceil(fm.descent - fm.ascent);
        if (w <= 0 || h <= 0) return null;
        Bitmap glyph = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        new Canvas(glyph).drawText(emoji, 0, -fm.ascent, text);

        // Find the flag inside the glyph's empty margins.
        int[] px = new int[w * h];
        glyph.getPixels(px, 0, w, 0, 0, w, h);
        int left = w, top = h, right = -1, bottom = -1;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                if ((px[y * w + x] >>> 24) > 200) {
                    if (x < left) left = x;
                    if (x > right) right = x;
                    if (y < top) top = y;
                    if (y > bottom) bottom = y;
                }
            }
        }
        if (right < left || bottom < top) return null;
        float fw = right - left + 1, fh = bottom - top + 1;
        if (fw / fh < 1.0f || fw / fh > 2.5f) return null; // not a flag shape (e.g. missing font)
        RectF flag = new RectF(left + fw * INSET_X, top + fh * INSET_Y, right + 1 - fw * INSET_X, bottom + 1 - fh * INSET_Y);

        float density = context.getResources().getDisplayMetrics().density;
        int outW = Math.round(WIDTH_DP * density);
        int outH = Math.round(HEIGHT_DP * density);
        RectF out = new RectF(0, 0, outW, outH);

        // Scale the flag to cover the output (cropping the longer side), centered.
        float scale = Math.max(outW / flag.width(), outH / flag.height());
        Matrix m = new Matrix();
        m.setTranslate(-flag.centerX(), -flag.centerY());
        m.postScale(scale, scale);
        m.postTranslate(outW / 2f, outH / 2f);
        BitmapShader shader = new BitmapShader(glyph, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
        shader.setLocalMatrix(m);
        Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
        fill.setShader(shader);

        Bitmap result = Bitmap.createBitmap(outW, outH, Bitmap.Config.ARGB_8888);
        float r = CORNER_DP * density;
        new Canvas(result).drawRoundRect(out, r, r, fill);
        glyph.recycle();
        return result;
    }
}
