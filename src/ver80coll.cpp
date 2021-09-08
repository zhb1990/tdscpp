#include "tdscpp.h"

using namespace std;

weak_ordering compare_strings_80(u16string_view val1, u16string_view val2, const tds::collation& coll) {
    // FIXME - get rid of unrecognized characters
    // FIXME - normalize
    // FIXME - case if necessary
    // FIXME - accents if necessary
    // FIXME - kana if necessary
    // FIXME - width if necessary
    // FIXME - sort

    throw runtime_error("FIXME");
}
