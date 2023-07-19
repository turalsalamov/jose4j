package org.jsoup.fuzzing.parser;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.jsoup.parser.ParseErrorList;

public class ParseErrorListFuzz {

    @FuzzTest
    void trackingTest(FuzzedDataProvider data) {

        int alpha = data.consumeInt();

        ParseErrorList.tracking(alpha);

    }


}
