package com.adshield;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Home screen widget: shows where your internet traffic appears to come from (your real
 * location, or your VPN server's when e.g. Surfshark is on), whether blocking is on, and a
 * big on/off button.
 *
 * Battery: it never updates on a timer. It redraws when blocking turns on or off or the
 * network changes, and re-checks the location only then or when you tap it.
 */
public class AdShieldWidget extends AppWidgetProvider {
    private static final String ACTION_REFRESH = "com.adshield.WIDGET_REFRESH";
    private static final long MIN_LOOKUP_INTERVAL_MS = 15_000;

    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private static long lastLookupMs;
    private static volatile boolean checking;

    @Override
    public void onUpdate(Context context, AppWidgetManager manager, int[] ids) {
        refresh(context, true, null);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);
        if (ACTION_REFRESH.equals(intent.getAction())) refresh(context, true, goAsync());
    }

    /** Redraws the widget without checking the location again. */
    static void redraw(Context context) {
        Context app = context.getApplicationContext();
        int[] ids = widgetIds(app);
        if (ids.length > 0) AppWidgetManager.getInstance(app).updateAppWidget(ids, views(app));
    }

    /** Redraws the widget and re-checks the location, unless that was done moments ago. */
    static void refresh(Context context) {
        refresh(context, false, null);
    }

    private static void refresh(Context context, boolean force, PendingResult pending) {
        Context app = context.getApplicationContext();
        int[] ids = widgetIds(app);
        if (ids.length == 0 || !shouldLookUp(force)) {
            redraw(app);
            if (pending != null) pending.finish();
            return;
        }
        checking = true;
        redraw(app);
        worker.execute(() -> {
            try {
                LocationLookup.Result r = LocationLookup.lookup();
                if (r != null) new Prefs(app).setLocation(r.flag, r.name);
            } finally {
                checking = false;
                redraw(app);
                if (pending != null) pending.finish();
            }
        });
    }

    private static synchronized boolean shouldLookUp(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && now - lastLookupMs < MIN_LOOKUP_INTERVAL_MS) return false;
        lastLookupMs = now;
        return true;
    }

    private static int[] widgetIds(Context app) {
        return AppWidgetManager.getInstance(app).getAppWidgetIds(new ComponentName(app, AdShieldWidget.class));
    }

    private static RemoteViews views(Context ctx) {
        Prefs prefs = new Prefs(ctx);
        boolean on = BlockerVpnService.running;
        RemoteViews v = new RemoteViews(ctx.getPackageName(), R.layout.widget);

        String location = prefs.locationName();
        v.setTextViewText(R.id.widget_flag, location.isEmpty() ? "🌐" : prefs.locationFlag()); // 🌐
        v.setTextViewText(R.id.widget_location, checking ? ctx.getString(R.string.widget_checking)
            : location.isEmpty() ? ctx.getString(R.string.widget_tap_location) : location);

        String status = on
            ? ctx.getString(R.string.widget_status_on, BlockerVpnService.blockedCount.get())
            : ctx.getString(prefs.wasReplacedByOtherVpn() ? R.string.widget_status_replaced : R.string.widget_status_off);
        v.setTextViewText(R.id.widget_status, status);
        v.setImageViewResource(R.id.widget_shield, on ? R.drawable.ic_widget_shield_on : R.drawable.ic_widget_shield_off);

        v.setTextViewText(R.id.widget_button, ctx.getString(on ? R.string.turn_off : R.string.turn_on));
        v.setInt(R.id.widget_button, "setBackgroundResource",
            on ? R.drawable.widget_button_off : R.drawable.widget_button_on);
        v.setTextColor(R.id.widget_button, on ? 0xFFFFFFFF : 0xFF000000);

        v.setOnClickPendingIntent(R.id.widget_button, PendingIntent.getActivity(ctx, 0,
            ToggleActivity.intent(ctx).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE));
        v.setOnClickPendingIntent(R.id.widget_location_row, PendingIntent.getBroadcast(ctx, 0,
            new Intent(ctx, AdShieldWidget.class).setAction(ACTION_REFRESH), PendingIntent.FLAG_IMMUTABLE));
        v.setOnClickPendingIntent(R.id.widget_shield, PendingIntent.getActivity(ctx, 1,
            new Intent(ctx, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
        return v;
    }
}
