# kt_v1 dataset manifest

Exported 2026-10-11 from the 53 runs of `experiments/results/kt_matrix_manifest.csv` with `datasets/scripts/to_yolo_format.py` (visibility cutoff 0.15 from `experiments/calibrate_visibility.py`, classes 0 car / 1 truck / 2 bus). Map: KIVI_Twin (Goethe-Schiller-Straße twin), camera 1280 x 720.

Split is by run, never by frame. Road 2 (static P3, windshield C) appears only in test. Test runs use seeds 7 and 8, train and val runs seeds 1 to 3. The angled bay R25-1249 is filled in runs captured before 2026-10-11 18:00 and empty afterwards (see `docs/thesis_plan.md`, session 6). Static runs have 300 frames; windshield runs end 20 m past the last bay (225 to 442 frames). P5 (Sparkasse lot) runs contain no traffic vehicles in view.

| Split | Runs | Frames | Boxes |
|---|---|---|---|
| train | 43 | 12139 | 109758 |
| val | 2 | 525 | 4868 |
| test | 8 | 2246 | 18042 |
| total | 53 | 14910 | 132668 |

| Run | Kind | View | Axis | Weather | Traffic | Fill | Seed | Split | Frames | Boxes |
|---|---|---|---|---|---|---|---|---|---|---|
| kt_static_P1_ClearNoon_u7 | static | P1 | test | ClearNoon | 30 | 0.6 | 7 | test | 300 | 3271 |
| kt_static_P3_ClearNoon_u8 | static | P3 | test | ClearNoon | 30 | 0.6 | 8 | test | 300 | 3392 |
| kt_static_P4_ClearNoon_u8 | static | P4 | test | ClearNoon | 30 | 0.6 | 8 | test | 300 | 2892 |
| kt_static_P5_CloudyNoon_u7 | static | P5 | test | CloudyNoon | 30 | 0.6 | 7 | test | 300 | 2400 |
| kt_wind_A_ClearNoon_u7 | wind | A | test | ClearNoon | 30 | 0.6 | 7 | test | 245 | 1533 |
| kt_wind_A_HardRainNoon_u8 | wind | A | test | HardRainNoon | 30 | 0.6 | 8 | test | 229 | 1431 |
| kt_wind_B_CloudyNoon_u7 | wind | B | test | CloudyNoon | 30 | 0.6 | 7 | test | 245 | 1713 |
| kt_wind_C_ClearNoon_u7 | wind | C | test | ClearNoon | 30 | 0.6 | 7 | test | 327 | 1410 |
| kt_static_P1_ClearNight_t3 | static | P1 | weather | ClearNight | 30 | 0.6 | 3 | train | 300 | 3368 |
| kt_static_P1_ClearNoon_t1 | static | P1 | baseline | ClearNoon | 30 | 0.6 | 1 | train | 300 | 4429 |
| kt_static_P1_ClearNoon_t1_traffic10 | static | P1 | traffic | ClearNoon | 10 | 0.6 | 1 | train | 300 | 3219 |
| kt_static_P1_ClearNoon_t2_fill30 | static | P1 | fill | ClearNoon | 30 | 0.3 | 2 | train | 300 | 2508 |
| kt_static_P1_ClearNoon_t2_traffic60 | static | P1 | traffic | ClearNoon | 60 | 0.6 | 2 | train | 300 | 3888 |
| kt_static_P1_ClearNoon_t3_fill100 | static | P1 | fill | ClearNoon | 30 | 1.0 | 3 | train | 300 | 5313 |
| kt_static_P1_ClearSunset_t2 | static | P1 | weather | ClearSunset | 30 | 0.6 | 2 | train | 300 | 3828 |
| kt_static_P1_CloudyNoon_t3 | static | P1 | weather | CloudyNoon | 30 | 0.6 | 3 | train | 300 | 3447 |
| kt_static_P1_HardRainNoon_t1 | static | P1 | weather | HardRainNoon | 30 | 0.6 | 1 | train | 300 | 4502 |
| kt_static_P2_ClearNoon_t1 | static | P2 | viewpoint | ClearNoon | 30 | 0.6 | 1 | train | 300 | 3645 |
| kt_static_P4_ClearNight_t3 | static | P4 | weather_area | ClearNight | 30 | 0.6 | 3 | train | 300 | 2594 |
| kt_static_P4_ClearNoon_t1 | static | P4 | viewpoint | ClearNoon | 30 | 0.6 | 1 | train | 300 | 2784 |
| kt_static_P4_ClearNoon_t1_fill30 | static | P4 | fill_area | ClearNoon | 30 | 0.3 | 1 | train | 300 | 1594 |
| kt_static_P4_ClearNoon_t2_fill100 | static | P4 | fill_area | ClearNoon | 30 | 1.0 | 2 | train | 300 | 3530 |
| kt_static_P4_ClearSunset_t2 | static | P4 | weather_area | ClearSunset | 30 | 0.6 | 2 | train | 300 | 3219 |
| kt_static_P4_CloudyNoon_t2 | static | P4 | weather_area | CloudyNoon | 30 | 0.6 | 2 | train | 300 | 3219 |
| kt_static_P4_HardRainNoon_t1 | static | P4 | weather_area | HardRainNoon | 30 | 0.6 | 1 | train | 300 | 2781 |
| kt_static_P4_WetCloudyNoon_t3 | static | P4 | weather_area | WetCloudyNoon | 30 | 0.6 | 3 | train | 300 | 2598 |
| kt_static_P5_ClearNight_t3 | static | P5 | weather_area | ClearNight | 30 | 0.6 | 3 | train | 300 | 1500 |
| kt_static_P5_ClearNoon_t1 | static | P5 | viewpoint | ClearNoon | 30 | 0.6 | 1 | train | 300 | 2100 |
| kt_static_P5_ClearNoon_t1_fill30 | static | P5 | fill_area | ClearNoon | 30 | 0.3 | 1 | train | 300 | 1800 |
| kt_static_P5_ClearNoon_t2_fill100 | static | P5 | fill_area | ClearNoon | 30 | 1.0 | 2 | train | 300 | 2400 |
| kt_static_P5_ClearSunset_t2 | static | P5 | weather_area | ClearSunset | 30 | 0.6 | 2 | train | 300 | 1200 |
| kt_static_P5_CloudyNoon_t2 | static | P5 | weather_area | CloudyNoon | 30 | 0.6 | 2 | train | 300 | 1200 |
| kt_static_P5_HardRainNoon_t1 | static | P5 | weather_area | HardRainNoon | 30 | 0.6 | 1 | train | 300 | 2100 |
| kt_static_P5_WetCloudyNoon_t3 | static | P5 | weather_area | WetCloudyNoon | 30 | 0.6 | 3 | train | 300 | 1500 |
| kt_wind_A_ClearNight_t3 | wind | A | weather | ClearNight | 30 | 0.6 | 3 | train | 225 | 1500 |
| kt_wind_A_ClearNoon_t1 | wind | A | baseline | ClearNoon | 30 | 0.6 | 1 | train | 230 | 1704 |
| kt_wind_A_ClearNoon_t1_stop | wind | A | stop | ClearNoon | 30 | 0.6 | 1 | train | 442 | 3226 |
| kt_wind_A_ClearNoon_t1_traffic10 | wind | A | traffic | ClearNoon | 10 | 0.6 | 1 | train | 230 | 1174 |
| kt_wind_A_ClearNoon_t2_fill30 | wind | A | fill | ClearNoon | 30 | 0.3 | 2 | train | 227 | 1337 |
| kt_wind_A_ClearNoon_t2_traffic60 | wind | A | traffic | ClearNoon | 60 | 0.6 | 2 | train | 230 | 2348 |
| kt_wind_A_ClearNoon_t3_fill100 | wind | A | fill | ClearNoon | 30 | 1.0 | 3 | train | 230 | 2093 |
| kt_wind_A_CloudyNoon_t2_stop | wind | A | stop | CloudyNoon | 30 | 0.6 | 2 | train | 442 | 3868 |
| kt_wind_A_CloudyNoon_t3 | wind | A | weather | CloudyNoon | 30 | 0.6 | 3 | train | 225 | 1499 |
| kt_wind_A_HardRainNoon_t2 | wind | A | weather | HardRainNoon | 30 | 0.6 | 2 | train | 230 | 2147 |
| kt_wind_A_WetCloudyNoon_t1 | wind | A | weather | WetCloudyNoon | 30 | 0.6 | 1 | train | 230 | 1700 |
| kt_wind_B_ClearNight_t3 | wind | B | weather_area | ClearNight | 30 | 0.6 | 3 | train | 227 | 1861 |
| kt_wind_B_ClearNoon_t1 | wind | B | viewpoint | ClearNoon | 30 | 0.6 | 1 | train | 245 | 2307 |
| kt_wind_B_ClearSunset_t2 | wind | B | weather_area | ClearSunset | 30 | 0.6 | 2 | train | 227 | 2326 |
| kt_wind_B_CloudyNoon_t2 | wind | B | weather_area | CloudyNoon | 30 | 0.6 | 2 | train | 227 | 2347 |
| kt_wind_B_HardRainNoon_t1 | wind | B | weather_area | HardRainNoon | 30 | 0.6 | 1 | train | 245 | 2235 |
| kt_wind_B_WetCloudyNoon_t3 | wind | B | weather_area | WetCloudyNoon | 30 | 0.6 | 3 | train | 227 | 1820 |
| kt_static_P1_WetCloudyNoon_t3 | static | P1 | weather | WetCloudyNoon | 30 | 0.6 | 3 | val | 300 | 3368 |
| kt_wind_A_ClearSunset_t3 | wind | A | weather | ClearSunset | 30 | 0.6 | 3 | val | 225 | 1500 |
