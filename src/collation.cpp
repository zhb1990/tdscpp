#include "tdscpp.h"
#include "tdscpp-private.h"

using namespace std;

namespace tds {
    string column::collation_name() const {
        string ret;

        if (coll.sort_id != 0) {
            switch (coll.sort_id) {
                case 30:
                    return coll.binary2 ? "SQL_Latin1_General_CP437_BIN2" : "SQL_Latin1_General_CP437_BIN";
                case 31:
                    return "SQL_Latin1_General_CP437_CS_AS";
                case 32:
                    return "SQL_Latin1_General_CP437_CI_AS";
                case 33:
                    return "SQL_Latin1_General_Pref_CP437_CI_AS";
                case 34:
                    return "SQL_Latin1_General_CP437_CI_AI";
                case 40:
                    return coll.binary2 ? "SQL_Latin1_General_CP850_BIN2" : "SQL_Latin1_General_CP850_BIN";
                case 41:
                    return "SQL_Latin1_General_CP850_CS_AS";
                case 42:
                    return "SQL_Latin1_General_CP850_CI_AS";
                case 43:
                    return "SQL_Latin1_General_Pref_CP850_CI_AS";
                case 44:
                    return "SQL_Latin1_General_CP850_CI_AI";
                case 49:
                    return "SQL_1xCompat_CP850_CI_AS";
                case 51:
                    return "SQL_Latin1_General_CP1_CS_AS";
                case 52:
                    return "SQL_Latin1_General_CP1_CI_AS";
                case 53:
                    return "SQL_Latin1_General_Pref_CP1_CI_AS";
                case 54:
                    return "SQL_Latin1_General_CP1_CI_AI";
                case 55:
                    return "SQL_AltDiction_CP850_CS_AS";
                case 56:
                    return "SQL_AltDiction_Pref_CP850_CI_AS";
                case 57:
                    return "SQL_AltDiction_CP850_CI_AI";
                case 58:
                    return "SQL_Scandinavian_Pref_CP850_CI_AS";
                case 59:
                    return "SQL_Scandinavian_CP850_CS_AS";
                case 60:
                    return "SQL_Scandinavian_CP850_CI_AS";
                case 61:
                    return "SQL_AltDiction_CP850_CI_AS";
                case 81:
                    return "SQL_Latin1_General_CP1250_CS_AS";
                case 82:
                    return "SQL_Latin1_General_CP1250_CI_AS";
                case 83:
                    return "SQL_Czech_CP1250_CS_AS";
                case 84:
                    return "SQL_Czech_CP1250_CI_AS";
                case 85:
                    return "SQL_Hungarian_CP1250_CS_AS";
                case 86:
                    return "SQL_Hungarian_CP1250_CI_AS";
                case 87:
                    return "SQL_Polish_CP1250_CS_AS";
                case 88:
                    return "SQL_Polish_CP1250_CI_AS";
                case 89:
                    return "SQL_Romanian_CP1250_CS_AS";
                case 90:
                    return "SQL_Romanian_CP1250_CI_AS";
                case 91:
                    return "SQL_Croatian_CP1250_CS_AS";
                case 92:
                    return "SQL_Croatian_CP1250_CI_AS";
                case 93:
                    return "SQL_Slovak_CP1250_CS_AS";
                case 94:
                    return "SQL_Slovak_CP1250_CI_AS";
                case 95:
                    return "SQL_Slovenian_CP1250_CS_AS";
                case 96:
                    return "SQL_Slovenian_CP1250_CI_AS";
                case 105:
                    return "SQL_Latin1_General_CP1251_CS_AS";
                case 106:
                    return "SQL_Latin1_General_CP1251_CI_AS";
                case 107:
                    return "SQL_Ukrainian_CP1251_CS_AS";
                case 108:
                    return "SQL_Ukrainian_CP1251_CI_AS";
                case 113:
                    return "SQL_Latin1_General_CP1253_CS_AS";
                case 114:
                    return "SQL_Latin1_General_CP1253_CI_AS";
                case 120:
                    return "SQL_MixDiction_CP1253_CS_AS";
                case 122:
                    return "SQL_AltDiction2_CP1253_CS_AS";
                case 124:
                    return "SQL_Latin1_General_CP1253_CI_AI";
                case 129:
                    return "SQL_Latin1_General_CP1254_CS_AS";
                case 130:
                    return "SQL_Latin1_General_CP1254_CI_AS";
                case 137:
                    return "SQL_Latin1_General_CP1255_CS_AS";
                case 138:
                    return "SQL_Latin1_General_CP1255_CI_AS";
                case 145:
                    return "SQL_Latin1_General_CP1256_CS_AS";
                case 146:
                    return "SQL_Latin1_General_CP1256_CI_AS";
                case 153:
                    return "SQL_Latin1_General_CP1257_CS_AS";
                case 154:
                    return "SQL_Latin1_General_CP1257_CI_AS";
                case 155:
                    return "SQL_Estonian_CP1257_CS_AS";
                case 156:
                    return "SQL_Estonian_CP1257_CI_AS";
                case 157:
                    return "SQL_Latvian_CP1257_CS_AS";
                case 158:
                    return "SQL_Latvian_CP1257_CI_AS";
                case 159:
                    return "SQL_Lithuanian_CP1257_CS_AS";
                case 160:
                    return "SQL_Lithuanian_CP1257_CI_AS";
                case 183:
                    return "SQL_Danish_Pref_CP1_CI_AS";
                case 184:
                    return "SQL_SwedishPhone_Pref_CP1_CI_AS";
                case 185:
                    return "SQL_SwedishStd_Pref_CP1_CI_AS";
                case 186:
                    return "SQL_Icelandic_Pref_CP1_CI_AS";
                case 210:
                    return "SQL_EBCDIC037_CP1_CS_AS";
                case 211:
                    return "SQL_EBCDIC1141_CP1_CS_AS"; // or SQL_EBCDIC273_CP1_CS_AS
                case 212:
                    return "SQL_EBCDIC277_CP1_CS_AS"; // or SQL_EBCDIC277_2_CP1_CS_AS
                case 213:
                    return "SQL_EBCDIC278_CP1_CS_AS";
                case 214:
                    return "SQL_EBCDIC280_CP1_CS_AS";
                case 215:
                    return "SQL_EBCDIC284_CP1_CS_AS";
                case 216:
                    return "SQL_EBCDIC285_CP1_CS_AS";
                case 217:
                    return "SQL_EBCDIC297_CP1_CS_AS";
                default:
                    return "";
            }
        }

        switch (coll.lcid) {
            case 1025:
                ret = "Arabic";
                break;

            case 1028:
                ret = "Chinese_Traditional_Stroke_Count";
                break;

            case 1029:
                ret = "Czech";
                break;

            case 1030:
                ret = "Danish_Norwegian";
                break;

            case 1032:
                ret = "Greek";
                break;

            case 1033:
                ret = "Latin1_General";
                break;

            case 1034:
                ret = "Traditional_Spanish";
                break;

            case 1035:
                ret = "Finnish_Swedish";
                break;

            case 1036:
                ret = "French";
                break;

            case 1037:
                ret = "Hebrew";
                break;

            case 1038:
                ret = "Hungarian";
                break;

            case 1039:
                ret = "Icelandic";
                break;

            case 1041:
                ret = coll.version >= 2 ? "Japanese_XJIS" : "Japanese";
                break;

            case 1042:
                ret = coll.version == 0 ? "Korean_Wansung" : "Korean";
                break;

            case 1044:
                ret = "Norwegian";
                break;

            case 1045:
                ret = "Polish";
                break;

            case 1047:
                ret = "Romansh";
                break;

            case 1048:
                ret = "Romanian";
                break;

            case 1049:
                ret = "Cyrillic_General";
                break;

            case 1050:
                ret = "Croatian";
                break;

            case 1051:
                ret = "Slovak";
                break;

            case 1052:
                ret = "Albanian";
                break;

            case 1054:
                ret = "Thai";
                break;

            case 1055:
                ret = "Turkish";
                break;

            case 1056:
                ret = "Urdu";
                break;

            case 1058:
                ret = "Ukrainian";
                break;

            case 1060:
                ret = "Slovenian";
                break;

            case 1061:
                ret = "Estonian";
                break;

            case 1062:
                ret = "Latvian";
                break;

            case 1063:
                ret = "Lithuanian";
                break;

            case 1065:
                ret = "Persian";
                break;

            case 1066:
                ret = "Vietnamese";
                break;

            case 1068:
                ret = "Azeri_Latin";
                break;

            case 1070:
                ret = "Upper_Sorbian";
                break;

            case 1071:
                ret = "Macedonian_FYROM";
                break;

            case 1081:
                ret = "Indic_General";
                break;

            case 1082:
                ret = "Maltese";
                break;

            case 1083:
                ret = "Sami_Norway";
                break;

            case 1087:
                ret = "Kazakh";
                break;

            case 1090:
                ret = "Turkmen";
                break;

            case 1091:
                ret = "Uzbek_Latin";
                break;

            case 1092:
                ret = "Tatar";
                break;

            case 1093:
                ret = "Bengali";
                break;

            case 1101:
                ret = "Assamese";
                break;

            case 1105:
                ret = "Tibetan";
                break;

            case 1106:
                ret = "Welsh";
                break;

            case 1107:
                ret = "Khmer";
                break;

            case 1108:
                ret = "Lao";
                break;

            case 1114:
                ret = "Syriac";
                break;

            case 1121:
                ret = "Nepali";
                break;

            case 1122:
                ret = "Frisian";
                break;

            case 1123:
                ret = "Pashto";
                break;

            case 1125:
                ret = "Divehi";
                break;

            case 1133:
                ret = "Bashkir";
                break;

            case 1146:
                ret = "Mapudungan";
                break;

            case 1148:
                ret = "Mohawk";
                break;

            case 1150:
                ret = "Breton";
                break;

            case 1152:
                ret = "Uighur";
                break;

            case 1153:
                ret = "Maori";
                break;

            case 1155:
                ret = "Corsican";
                break;

            case 1157:
                ret = "Yakut";
                break;

            case 1164:
                ret = "Dari";
                break;

            case 2052:
                ret = "Chinese_Simplified_Pinyin";
                break;

            case 2074:
                ret = "Serbian_Latin";
                break;

            case 2092:
                ret = "Azeri_Cyrillic";
                break;

            case 2107:
                ret = "Sami_Sweden_Finland";
                break;

            case 2143:
                ret = "Tamazight";
                break;

            case 3076:
                ret = "Chinese_Hong_Kong_Stroke";
                break;

            case 3082:
                ret = "Modern_Spanish";
                break;

            case 3098:
                ret = "Serbian_Cyrillic";
                break;

            case 5124:
                ret = "Chinese_Traditional_Pinyin";
                break;

            case 5146:
                ret = "Bosnian_Latin";
                break;

            case 8218:
                ret = "Bosnian_Cyrillic";
                break;

            case 66567:
                ret = "German_PhoneBook";
                break;

            case 66574:
                ret = "Hungarian_Technical";
                break;

            case 66577:
                ret = "Japanese_Unicode";
                break;

            case 66615:
                ret = "Georgian_Modern_Sort";
                break;

            case 133124:
                ret = "Chinese_Simplified_Stroke_Order";
                break;

            case 136196:
                ret = "Chinese_Traditional_Stroke_Order";
                break;

            case 197636:
                ret = "Chinese_Traditional_Bopomofo";
                break;

            case 263185:
                ret = "Japanese_Bushu_Kakusu";
                break;

            default:
                return "";
        }

        switch (coll.version) {
            case 0:
                break;

            case 1:
                ret += "_90";
                break;

            case 2:
                ret += "_100";
                break;

            case 3:
                ret += "_140";
                break;

            default:
                return "";
        }

        if (coll.binary2)
            ret += "_BIN2";
        else if (coll.binary)
            ret += "_BIN";
        else {
            ret += coll.ignore_case ? "_CI" : "_CS";
            ret += coll.ignore_accent ? "_AI" : "_AS";

            if (!coll.ignore_kana)
                ret += "_KS";

            if (!coll.ignore_width)
                ret += "_WS";
        }

        // no way to detect _SC (indicates UTF-16 rather than UCS-2)
        // ditto for _VSS

        if (coll.utf8)
            ret += (coll.version >= 3 || coll.binary2) ? "_UTF8" : "_SC_UTF8";

        return ret;
    }

    weak_ordering column::operator<=>(const column& c) const {
        switch (type) {
            case sql_type::INTN:
            case sql_type::TINYINT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::BIGINT: {
                auto v1 = (int64_t)*this;
                auto v2 = (int64_t)c;

                return v1 <=> v2;
            }

            case sql_type::DATE: {
                auto v1 = (chrono::year_month_day)*this;
                auto v2 = (chrono::year_month_day)c;

                return v1 <=> v2;
            }

            // FIXME - VARCHAR
            // FIXME - CHAR
            // FIXME - NVARCHAR
            // FIXME - NCHAR
            // FIXME - TEXT
            // FIXME - NTEXT
            // FIXME - XML
            // FIXME - IMAGE
            // FIXME - UNIQUEIDENTIFIER
            // FIXME - TIME
            // FIXME - DATETIME2
            // FIXME - DATETIMEOFFSET
            // FIXME - BIT
            // FIXME - DATETIM4
            // FIXME - REAL
            // FIXME - MONEY
            // FIXME - DATETIME
            // FIXME - FLOAT
            // FIXME - SQL_VARIANT
            // FIXME - BITN
            // FIXME - DECIMAL
            // FIXME - NUMERIC
            // FIXME - FLTN
            // FIXME - MONEYN
            // FIXME - DATETIMN
            // FIXME - SMALLMONEY
            // FIXME - VARBINARY
            // FIXME - BINARY
            // FIXME - UDT

            default:
                throw formatted_error("Comparison for type {} unimplemented.", type);
        }
    }
};
