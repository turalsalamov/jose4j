package org.jsoup.fuzzing.parser;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.jsoup.nodes.Element;
import org.jsoup.parser.HtmlTreeBuilder;
import org.jsoup.parser.Parser;

public class ParserFuzz {
    Parser parser = new Parser(new HtmlTreeBuilder());
    @FuzzTest
    void parseInputTest(FuzzedDataProvider data) {


        String html = data.consumeString(100);
        String baseUri = data.consumeString(100);


        parser.parseInput(html, baseUri);
    }

    @FuzzTest
    void parseFragmentInputTest(FuzzedDataProvider data) {
        String tag = data.consumeString(30);
        Element element = new Element(tag);
        String  fragment = data.consumeString(100);
        String baseUri = data.consumeString(100);

        parser.parseFragmentInput(fragment, element, baseUri);

    }

    @FuzzTest
    void isContentForTagDataTest(FuzzedDataProvider data) {
        String normalName = data.consumeString(100);

        parser.isContentForTagData(normalName);

    }

    @FuzzTest
    void parseTest(FuzzedDataProvider data) {

        String html = data.consumeString(100);
        String baseUri = data.consumeString(100);

        Parser.parse(html, baseUri);
    }


}
