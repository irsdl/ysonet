"""File names: the format-word trap, and where truncation cuts."""

from . import support  # noqa: F401

import unittest

from refslib import slugs

BIRCH = ("https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/"
         "Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based"
         "%20Serialization%20Vulnerabilities%20in%20.NET-whitepaper.pdf")


class TestGenericLinkText(unittest.TestCase):
    """A reading list cites a paper as `[Whitepaper](...)` and its deck as
    `[Slides](...)`. Taken as titles, those produced `whitepaper.md` and
    `slides.md`: two unrelated documents named after their file type, neither
    findable by anyone looking for the talk."""

    def test_a_format_word_is_not_a_title(self):
        for label in ("Whitepaper", "Slides", "PDF", "here", "Read more"):
            self.assertTrue(slugs.is_generic(label), label)

    def test_a_real_title_is_left_alone(self):
        for title in ("Attacking .NET Serialization", "Whitepaper on BinaryFormatter",
                      "Friday the 13th: JSON Attacks"):
            self.assertFalse(slugs.is_generic(title), title)

    def test_the_url_supplies_the_title_when_the_link_text_will_not(self):
        title = slugs.readable_title("Whitepaper", BIRCH)
        self.assertIn("Jonathan Birch", title)
        self.assertIn("Second Breakfast", title)

    def test_a_url_that_says_nothing_either_falls_back_to_the_host(self):
        """`https://soroush.me/blog` gave the title "Blog" and so a file called
        `blog.md`, which names no source at all."""
        self.assertEqual(slugs.build(slugs.readable_title("Blog", "https://soroush.me/blog")),
                         "soroush-me-blog")

    def test_a_slug_that_is_only_a_format_word_is_rebuilt_not_kept(self):
        self.assertEqual(slugs.pinned("whitepaper"), "")
        self.assertEqual(slugs.pinned("slides"), "")

    def test_an_ordinary_slug_stays_pinned(self):
        self.assertEqual(slugs.pinned("2023-zdi-exploiting-hardened-deserialization"),
                         "2023-zdi-exploiting-hardened-deserialization")


class TestTruncation(unittest.TestCase):
    """The tail is where the discriminator lives: two citations of one talk
    differ only by a final `whitepaper`, so cutting the tail made both slugs
    identical and the second became `...-2`."""

    def test_the_last_word_survives_a_long_title(self):
        built = slugs.build("Second Breakfast Implicit and Mutation Based Serialization "
                            "Vulnerabilities in Dot Net whitepaper")
        self.assertLessEqual(len(built), slugs.MAX_LENGTH)
        self.assertTrue(built.endswith("whitepaper"), built)

    def test_two_long_titles_differing_only_at_the_end_get_different_slugs(self):
        stem = "Second Breakfast Implicit and Mutation Based Serialization Vulnerabilities"
        self.assertNotEqual(slugs.build(stem + " whitepaper"), slugs.build(stem + " slides"))

    def test_a_short_title_is_untouched(self):
        self.assertEqual(slugs.build("JSON Attacks", "NCC", "2017"),
                         "2017-ncc-json-attacks")


if __name__ == "__main__":
    unittest.main()
