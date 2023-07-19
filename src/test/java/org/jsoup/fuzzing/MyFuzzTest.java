package org.jsoup.fuzzing;

import org.jsoup.parser.CharacterReader;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.jsoup.parser.ParseErrorList;


import java.io.StringReader;

class MyFuzzTest {
    @FuzzTest
    void trackNewLinesTest(FuzzedDataProvider data) {
        CharacterReader cr = new CharacterReader(new StringReader("a"), 15);

        boolean alpha = data.consumeBoolean();

        cr.trackNewlines(alpha);

    }
    @FuzzTest
    void lineNumberTest(FuzzedDataProvider data) {
        CharacterReader cr = new CharacterReader(new StringReader("a"), 15);

        char alpha = data.consumeChar();

        cr.consumeTo(alpha);

    }

    @FuzzTest
    void consumeToAnyTest(FuzzedDataProvider data){
        CharacterReader cr = new CharacterReader(new StringReader("a"), 15);

        char alpha = data.consumeChar();

        cr.consumeToAny(alpha);
    }

    @FuzzTest
    void trackingTest(FuzzedDataProvider data) {

        int alpha = data.consumeInt();

        ParseErrorList.tracking(alpha);

    }

}
