/*
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <Arduino.h>   // <<< REQUIRED FIRST
#include <Wire.h>   // REQUIRED for TwoWire type
#include "config.h"

extern long  DELAY_TASK_DISPLAY;
extern bool  TICK_DELAY_TASK_DISPLAY;

extern long  DELAY_TASK_SERIAL_INFOCMD;
extern bool  TICK_DELAY_TASK_SERIAL_INFOCMD;

extern long  DELAY_TASK_MULTIPLEXERS;
extern bool  TICK_DELAY_TASK_MULTIPLEXERS;

extern long  DELAY_TASK_GYRO0;
extern bool  TICK_DELAY_TASK_GYRO0;

extern long  DELAY_TASK_UNIVERSE;
extern bool  TICK_DELAY_TASK_UNIVERSE;

extern long  DELAY_TASK_GPS;
extern bool  TICK_DELAY_TASK_GPS;

extern long  DELAY_TASK_SWITCHES;
extern bool  TICK_DELAY_TASK_SWITCHES;

extern long  DELAY_TASK_PORTCONTROLLER_INPUT;
extern bool  TICK_DELAY_TASK_PORTCONTROLLER_INPUT;

extern long  DELAY_TASK_STORAGE;
extern bool  TICK_DELAY_TASK_STORAGE;

extern long  DELAY_TASK_LOGGING;
extern bool  TICK_DELAY_TASK_LOGGING;

extern bool global_task_sync;
extern long system_sync_retry_max;

extern bool ISR_Bool_MultiDisplayController_0;

#define EARTH_MEAN_RADIUS 6371000.0 // Mean Earth radius (meters)

// ----------------------------------------------------------------------------------------
// Power & POWER_CONFIG_ULTIMATE_PERFORMANCE.
// ----------------------------------------------------------------------------------------
/*
    Tasks using TICK_DELAY_xxx false will use millisecond timing. 
    Tasks DELAY_TASK_xxx can be milliseconds or ticks according to TICK_DELAY_xxx.
*/
// ----------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------
// Power & POWER_CONFIG_ULTIMATE_PERFORMANCE – mutable at runtime, no multiple-definition errors
// ----------------------------------------------------------------------------------------


#define POWER_CONFIG_1_SECOND_DELAY_TASK_SERIAL_INFOCMD              1
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_SERIAL_INFOCMD         true

#define POWER_CONFIG_1_SECOND_DELAY_TASK_MULTIPLEXERS                1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_MULTIPLEXERS           false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_GYRO                        1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_GYRO                   false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_UNIVERSE                    1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_UNIVERSE               false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_GPS                         1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_GPS                    false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_SWITCHES                    1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_SWITCHES               false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_PORTCONTROLLER_INPUT        1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_PORTCONTROLLER_INPUT   false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_STORAGE                     500
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_STORAGE                false

#define POWER_CONFIG_1_SECOND_DELAY_TASK_LOGGING                     1000
#define POWER_CONFIG_1_SECOND_TICK_DELAY_TASK_LOGGING                false

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_MULTI_DISPLAY               10
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_MULTI_DISPLAY          false

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_SERIAL_INFOCMD              1
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_SERIAL_INFOCMD         true

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_MULTIPLEXERS                1
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_MULTIPLEXERS           true

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_GYRO                        1
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_GYRO                   true

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_UNIVERSE                    1000
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_UNIVERSE               false

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_GPS                         1
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_GPS                    true

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_SWITCHES                    1
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_SWITCHES               true

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_PORTCONTROLLER_INPUT        1000
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_PORTCONTROLLER_INPUT   false

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_STORAGE                     500
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_STORAGE                false

#define POWER_CONFIG_ULTIMATE_PERFORMANCE_DELAY_TASK_LOGGING                     1000
#define POWER_CONFIG_ULTIMATE_PERFORMANCE_TICK_DELAY_TASK_LOGGING                false

// ----------------------------------------------------------------------------------------
// Buffers.
// ----------------------------------------------------------------------------------------
#define MAX_GLOBAL_SERIAL_BUFFER_SIZE 512
#define MAX_GLOBAL_ELEMENT_SIZE 56
#define MAX_INPUT_PORTCONTROLLER_RESPONSE_BYTES 32
// ----------------------------------------------------------------------------------------
// FS.
// ----------------------------------------------------------------------------------------
#define FORMAT_SPIFFS_IF_FAILED false
// ----------------------------------------------------------------------------------------
// Gyro.
// ----------------------------------------------------------------------------------------
#define GYRO_0_ACC_UPDATE   0x01
#define GYRO_0_UPDATE		0x02
#define GYRO_0_ANGLE_UPDATE	0x04
#define GYRO_0_MAG_UPDATE	0x08
#define GYRO_0_READ_UPDATE  0x80
// ----------------------------------------------------------------------------------------
// GPS.
// ----------------------------------------------------------------------------------------
#define MAX_GNGGA_ELEMENTS 16
#define MAX_GNRMC_ELEMENTS 14
#define MAX_GPATT_ELEMENTS 41
// ----------------------------------------------------------------------------------------
// Checksum.
// ----------------------------------------------------------------------------------------
#define MAX_CHECKSUM_SIZE 10
#define MAX_CHEKSUM_SUM_SIZE 4
// ----------------------------------------------------------------------------------------
// Mapping.
// ----------------------------------------------------------------------------------------
#define MAX_MAPPABLE_VALUES 32   // Maximum number of mappable values
#define MAX_MAPPING_PARAMETERS 6 // Number of parameters per mapping slot
#define MAX_MAP_SLOTS 70        // Maximum number of map slots.
#define MAX_MAP_MODES 3
#define INDEX_MAPPABLE_VALUES_DIGITAL      0
#define INDEX_MAPPABLE_VALUES_YAWGPATT     1
#define INDEX_MAPPABLE_VALUES_ROLLGPATT    2
#define INDEX_MAPPABLE_VALUES_PITCHGPATT   3
#define INDEX_MAPPABLE_VALUES_GYRO0ACCX    4
#define INDEX_MAPPABLE_VALUES_GYRO0ACCY    5
#define INDEX_MAPPABLE_VALUES_GYRO0ACCZ    6
#define INDEX_MAPPABLE_VALUES_GYRO0ANGX    7
#define INDEX_MAPPABLE_VALUES_GYRO0ANGY    8
#define INDEX_MAPPABLE_VALUES_GYRO0ANGZ    9
#define INDEX_MAPPABLE_VALUES_GYRO0MAGX    10
#define INDEX_MAPPABLE_VALUES_GYRO0MAGY    11
#define INDEX_MAPPABLE_VALUES_GYRO0MAGZ    12
#define INDEX_MAPPABLE_VALUES_GYRO0GYROX   13
#define INDEX_MAPPABLE_VALUES_GYRO0GYROY   14
#define INDEX_MAPPABLE_VALUES_GYRO0GYROZ   15
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_0   16
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_1   17
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_2   18
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_3   19
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_4   20
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_5   21
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_6   22
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_7   23
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_8   24
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_9   25
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_10  26
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_11  27
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_12  28
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_13  29
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_14  30
#define INDEX_MAPPABLE_VALUES_ADMPLEX0_15  31
// standard map
#define INDEX_MAP_VALUE 0
#define INDEX_MAP_EMIN  1 // expected min
#define INDEX_MAP_EMAX  2 // expected max
#define INDEX_MAP_OMIN  3 // output min
#define INDEX_MAP_OMAX  4 // output max
// center map
#define INDEX_CMAP_VALUE     0
#define INDEX_CMAP_CENTER    1 // approximate center value.
#define INDEX_CMAP_NEG_RANGE 2 // 0 to approximate center value (approximate center value).
#define INDEX_CMAP_POS_RANGE 3 // ADC max - neg range.
#define INDEX_CMAP_OMAX      4 // maximum resulting value.
#define INDEX_CMAP_DEADZONE  5 // expected flutuation at center.
// map mode
#define MAP_MIN_TO_MAX 0 // normal map
#define MAP_CENTER_X0  1 // center map and select axis 0 (a side of center)
#define MAP_CENTER_X1  2 // center map and select axis 1 (opposite side of center)

// ----------------------------------------------------------------------------------------
// INS.
// ----------------------------------------------------------------------------------------
#define INS_INITIALIZATION_FLAG_0 0
#define INS_INITIALIZATION_FLAG_1 1
#define INS_INITIALIZATION_FLAG_2 2
#define INS_INITIALIZATION_FLAG_3 3
#define INS_INITIALIZATION_FLAG_4 4
#define MAX_INS_INITIALIZATION_FLAG 4
#define INS_MODE_OFF 0
#define INS_MODE_DYNAMIC 1
#define INS_MODE_HOLD_THE_LINE 2
#define MAX_INS_MODE 3
// ----------------------------------------------------------------------------------------
// Matrix.
// ----------------------------------------------------------------------------------------
#define MAX_MATRIX_OUTPUT_MODES 2
#define MAX_MATRIX_OVERRIDE_TIME 1000000
#define MAX_MATRIX_SWITCHES 70         // logical max is current subjective max<=sytem memory capacity (actual max is subjective max<=sytem memory capacity and or limited by portcontroller max I/O range if using port controller for output)
#define MAX_MATRIX_SWITCH_FUNCTIONS 10 // logical max is current subjective max<=sytem memory capacity (actual max is subjective max<=sytem memory capacity and or limited by portcontroller max I/O range if using port controller for output)
#define MAX_MATRIX_FUNCTION_NAMES 87 // should match length matrixData.matrix_function_names[]
#define MAX_MATRIX_OPERATORS 5
#define INDEX_MATRIX_FUNTION_X 0
#define INDEX_MATRIX_FUNTION_Y 1
#define INDEX_MATRIX_FUNTION_Z 2
#define INDEX_MATRIX_SWITCH_OPERATOR_NONE 0
#define INDEX_MATRIX_SWITCH_OPERATOR_EQUAL 1
#define INDEX_MATRIX_SWITCH_OPERATOR_OVER 2
#define INDEX_MATRIX_SWITCH_OPERATOR_UNDER 3
#define INDEX_MATRIX_SWITCH_OPERATOR_RANGE 4

#define INDEX_MATRIX_SWITCH_FUNCTION_NONE 0
#define INDEX_MATRIX_SWITCH_FUNCTION_ON 1
#define INDEX_MATRIX_SWITCH_FUNCTION_SWITCHLINK 2
#define INDEX_MATRIX_SWITCH_FUNCTION_LOCALTIME 3
#define INDEX_MATRIX_SWITCH_FUNCTION_WEEKDAY 4
#define INDEX_MATRIX_SWITCH_FUNCTION_DATEDAYX 5
#define INDEX_MATRIX_SWITCH_FUNCTION_DATEMONTHX 6
#define INDEX_MATRIX_SWITCH_FUNCTION_DATEYEARX 7
#define INDEX_MATRIX_SWITCH_FUNCTION_DEGLAT 8
#define INDEX_MATRIX_SWITCH_FUNCTION_DEGLON 9
#define INDEX_MATRIX_SWITCH_FUNCTION_INSLAT 10
#define INDEX_MATRIX_SWITCH_FUNCTION_INSLON 11
#define INDEX_MATRIX_SWITCH_FUNCTION_INSHEADING 12
#define INDEX_MATRIX_SWITCH_FUNCTION_INSALTITUDE 13
#define INDEX_MATRIX_SWITCH_FUNCTION_POSSTATUSGNGGA 14
#define INDEX_MATRIX_SWITCH_FUNCTION_SATCOUNT 15
#define INDEX_MATRIX_SWITCH_FUNCTION_GPSPRECISION 16
#define INDEX_MATRIX_SWITCH_FUNCTION_ALTGNGGA 17
#define INDEX_MATRIX_SWITCH_FUNCTION_GSPEEDGNRMC 18
#define INDEX_MATRIX_SWITCH_FUNCTION_HEADINGGNRMC 19
#define INDEX_MATRIX_SWITCH_FUNCTION_LFLAGGPATT 20
#define INDEX_MATRIX_SWITCH_FUNCTION_SFLAGGPATT 21
#define INDEX_MATRIX_SWITCH_FUNCTION_RSFLAGGPATT 22
#define INDEX_MATRIX_SWITCH_FUNCTION_INSGPATT 23
#define INDEX_MATRIX_SWITCH_FUNCTION_SPEEDNUMGPATT 24
#define INDEX_MATRIX_SWITCH_FUNCTION_MILEAGEGPATT 25
#define INDEX_MATRIX_SWITCH_FUNCTION_GSTDATAGPATT 26
#define INDEX_MATRIX_SWITCH_FUNCTION_YAWGPATT 27
#define INDEX_MATRIX_SWITCH_FUNCTION_ROLLGPATT 28
#define INDEX_MATRIX_SWITCH_FUNCTION_PITCHGPATT 29
#define INDEX_MATRIX_SWITCH_FUNCTION_GNGGAVALIDCS 30
#define INDEX_MATRIX_SWITCH_FUNCTION_GNRMCVALIDCS 31
#define INDEX_MATRIX_SWITCH_FUNCTION_GPATTVALIDCS 32
#define INDEX_MATRIX_SWITCH_FUNCTION_GNGGAVALIDCD 33
#define INDEX_MATRIX_SWITCH_FUNCTION_GNRMCVALIDCD 34
#define INDEX_MATRIX_SWITCH_FUNCTION_GPATTVALIDCD 35
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ACCX 36
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ACCY 37
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ACCZ 38
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ANGX 39
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ANGY 40
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0ANGZ 41
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0MAGX 42
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0MAGY 43
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0MAGZ 44
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0GYROX 45
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0GYROY 46
#define INDEX_MATRIX_SWITCH_FUNCTION_GYRO0GYROZ 47
#define INDEX_MATRIX_SWITCH_FUNCTION_METEORS 48
#define INDEX_MATRIX_SWITCH_FUNCTION_SUNAZ 49
#define INDEX_MATRIX_SWITCH_FUNCTION_SUNALT 50
#define INDEX_MATRIX_SWITCH_FUNCTION_MOONAZ 51
#define INDEX_MATRIX_SWITCH_FUNCTION_MOONALT 52
#define INDEX_MATRIX_SWITCH_FUNCTION_MOONPHASE 53
#define INDEX_MATRIX_SWITCH_FUNCTION_MERCURYAZ 54
#define INDEX_MATRIX_SWITCH_FUNCTION_MERCURYALT 55
#define INDEX_MATRIX_SWITCH_FUNCTION_VENUSAZ 56
#define INDEX_MATRIX_SWITCH_FUNCTION_VENUSALT 57
#define INDEX_MATRIX_SWITCH_FUNCTION_MARSAZ 58
#define INDEX_MATRIX_SWITCH_FUNCTION_MARSALT 59
#define INDEX_MATRIX_SWITCH_FUNCTION_JUPITERAZ 60
#define INDEX_MATRIX_SWITCH_FUNCTION_JUPITERALT 61
#define INDEX_MATRIX_SWITCH_FUNCTION_SATURNAZ 62
#define INDEX_MATRIX_SWITCH_FUNCTION_SATURNALT 63
#define INDEX_MATRIX_SWITCH_FUNCTION_URANUSAZ 64
#define INDEX_MATRIX_SWITCH_FUNCTION_URANUSALT 65
#define INDEX_MATRIX_SWITCH_FUNCTION_NEPTUNEAZ 66
#define INDEX_MATRIX_SWITCH_FUNCTION_NEPTUNEALT 67
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNGGANORTH 68
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNGGASOUTH 69
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNGGAEAST 70
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNGGAWEST 71
#define INDEX_MATRIX_SWITCH_FUNCTION_POSSTATUSGNRMCA 72
#define INDEX_MATRIX_SWITCH_FUNCTION_POSSTATUSGNRMCV 73
#define INDEX_MATRIX_SWITCH_FUNCTION_MODEGNRMCA 74
#define INDEX_MATRIX_SWITCH_FUNCTION_MODEGNRMCD 75
#define INDEX_MATRIX_SWITCH_FUNCTION_MODEGNRMCE 76
#define INDEX_MATRIX_SWITCH_FUNCTION_MODEGNRMCN 77
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNRMCNORTH 78
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNRMCSOUTH 79
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNRMCEAST 80
#define INDEX_MATRIX_SWITCH_FUNCTION_HEMIGNRMCWEST 81
#define INDEX_MATRIX_SWITCH_FUNCTION_ADMPLEX0 82
#define INDEX_MATRIX_SWITCH_FUNCTION_MAPPEDVALUE 83
#define INDEX_MATRIX_SWITCH_FUNCTION_SDCARDINSERTED 84
#define INDEX_MATRIX_SWITCH_FUNCTION_SDCARDMOUNTED 85
#define INDEX_MATRIX_SWITCH_FUNCTION_PCINPUTVALUE 86

#define INDEX_MATRIX_MOD_0 0
#define INDEX_MATRIX_MOD_1 1
// ----------------------------------------------------------------------------------------
// TCA9548A I2C multiplexer address.
// ----------------------------------------------------------------------------------------
#define TCA9548AADDR_0 0x70
#define MAX_IIC_MUX_CHANNELS 8
// ----------------------------------------------------------------------------------------
// CH74HC4067 analog/digital multiplexer pins (Mux 0).
// ----------------------------------------------------------------------------------------
#define ADMPLEX_0_S0 23
#define ADMPLEX_0_S1 22
#define ADMPLEX_0_S2 21
#define ADMPLEX_0_S3 20
#define ADMPLEX_0_SIG 53
#define MAX_AD_MUX 1               // Maximum number of analog/digital multiplexers (CH74HC4067).
#define MAX_AD_MUX_CONTROL_PINS 4  // Number of control pins for CH74HC4067 (S0-S3).
#define MAX_AD_MUX_CHANNELS 16     // Number of channels for CH74HC4067.
#define INDEX_ADMPLEX_0_CH_0 0
#define INDEX_ADMPLEX_0_CH_1 1
#define INDEX_ADMPLEX_0_CH_2 2
#define INDEX_ADMPLEX_0_CH_3 3
#define INDEX_ADMPLEX_0_CH_4 4
#define INDEX_ADMPLEX_0_CH_5 5
#define INDEX_ADMPLEX_0_CH_6 6
#define INDEX_ADMPLEX_0_CH_7 7
#define INDEX_ADMPLEX_0_CH_8 8
#define INDEX_ADMPLEX_0_CH_9 9
#define INDEX_ADMPLEX_0_CH_10 10
#define INDEX_ADMPLEX_0_CH_11 11
#define INDEX_ADMPLEX_0_CH_12 12
#define INDEX_ADMPLEX_0_CH_13 13
#define INDEX_ADMPLEX_0_CH_14 14
#define INDEX_ADMPLEX_0_CH_15 15
// ----------------------------------------------------------------------------------------
// Volcanos.
// ----------------------------------------------------------------------------------------
#define MAX_VOLCANOS 435
#define MAX_LOCATIONS 57
#define MAX_TYPES 19
// ----------------------------------------------------------------------------------------
// Meteors.
// ----------------------------------------------------------------------------------------
#define MAX_METEOR_SHOWERS                8
#define MAX_METEOR_RESULT_ELEMENTS        2
#define INDEX_METEOR_RESULT_DATETIME      0
#define INDEX_METEOR_RESULT_PEAK_DATETIME 1
// datetime
#define MAX_METEOR_SHOWER_DATETIME          2
#define MAX_METEOR_SHOWER_DATETIME_ELEMENTS 2
#define INDEDX_METEOR_DATETIME_START        0
#define INDEDX_METEOR_DATETIME_END          1
#define INDEDX_METEOR_DATETIME_MONTH_START  0
#define INDEDX_METEOR_DATETIME_DAY_START    1
#define INDEDX_METEOR_DATETIME_MONTH_END    0
#define INDEDX_METEOR_DATETIME_DAY_END      1
// peak datetime
#define MAX_METEOR_SHOWER_PEAK_DATETIME               2
#define MAX_METEOR_SHOWER_PEAK_DATETIME_ELEMENTS      3
#define INDEDX_METEOR_PEAK_DATETIME_START             0
#define INDEDX_METEOR_PEAK_DATETIME_END               1
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_0_START     0
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_0_DAY_START 1
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_0_DAY_END   2
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_1_END       0
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_1_DAY_START 1
#define INDEDX_METEOR_PEAK_DATETIME_MONTH_1_DAY_END   2
// ----------------------------------------------------------------------------------------
// SatIO.
// ----------------------------------------------------------------------------------------
#define MAX_DAYS_OF_THE_WEEK 7

#define MAX_COORDINATE_CONVERSION_CONVERSION_MODES 2
#define COORDINATE_CONVERSION_MODE_STATIC          0
#define COORDINATE_CONVERSION_MODE_GPS             1


#define MAX_ALTITUDE_UNIT_MODES       3
#define ALTITUDE_UNIT_MODE_METERS     0
#define ALTITUDE_UNIT_MODE_MILES      1
#define ALTITUDE_UNIT_MODE_KILOMETERS 2

#define MAX_ALTITUDE_CONVERSION_MODES   2
#define ALTITUDE_CONVERSION_MODE_STATIC 0
#define ALTITUDE_CONVERSION_MODE_GPS    1


#define MAX_SPEED_UNIT_MODES            4 // Number of speed conversion modes
#define SPEED_UNIT_MODE_METERS_A_SECOND 0
#define SPEED_UNIT_MODE_MPH             1
#define SPEED_UNIT_MODE_KPH             2
#define SPEED_UNIT_MODE_KTS             3

#define MAX_SPEED_CONVERSIO_MODES    2
#define SPEED_CONVERSION_MODE_STATIC 0
#define SPEED_CONVERSION_MODE_GPS    1

#define METERS_TO_MILES_RATIO      0.000621371
#define METERS_TO_KILOMETERS_RATIO 0.001

#define METERS_TO_MPH_RATIO 2.23694
#define METERS_TO_KPH_RATIO 3.6
#define METERS_TO_KTS_RATIO 1.94384

#define KNOTS_TO_METERS_PER_SECOND 0.514444
#define KNOTS_TO_MPH 1.15078
#define KNOTS_TO_KPH 1.852

#define MAX_GROUND_HEADING_MODES   2
#define GROUND_HEADING_MODE_STATIC 0
#define GROUND_HEADING_MODE_GPS    1


#define LAST_EPOCH 1900
// ----------------------------------------------------------------------------------------
// SIDEREAL HELPER.
// ----------------------------------------------------------------------------------------
#define INDEX_SIDEREAL_STAR_TABLE 0          
#define INDEX_SIDEREAL_NGC_TABLE 1           // New General Catalogue
#define INDEX_SIDEREAL_IC_TABLE 2            // The Index Catalogue of Nebulae and Clusters of Stars (IC)
#define INDEX_SIDEREAL_MESSIER_TABLE 3       
#define INDEX_SIDEREAL_CALDWELL_TABLE 4      
#define INDEX_SIDEREAL_HERSHEL400_TABLE 5    
#define INDEX_SIDEREAL_OTHER_OBJECTS_TABLE 6

#endif // CONFIG_H