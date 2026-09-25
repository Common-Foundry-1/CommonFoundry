//! Isolated, optimized regression for the Linux wallet's patched GLib source.
//! No wallet, node, network or GPU is opened.

#[cfg(test)]
mod tests {
    use glib::prelude::*;

    #[test]
    fn glib_variant_string_iterator_methods_preserve_values() {
        let values = ["alpha", "beta", "", "delta", "omega"];
        let value = values.to_variant();
        assert_eq!(value.array_iter_str().unwrap().collect::<Vec<_>>(), values);

        let mut forward = value.array_iter_str().unwrap();
        assert_eq!(forward.next(), Some("alpha"));
        assert_eq!(forward.nth(1), Some(""));
        assert_eq!(forward.next_back(), Some("omega"));
        assert_eq!(forward.last(), Some("delta"));

        let mut backward = value.array_iter_str().unwrap();
        assert_eq!(backward.nth_back(1), Some("delta"));
        assert_eq!(backward.nth(1), Some("beta"));
        assert_eq!(backward.next(), Some(""));
        assert_eq!(backward.next(), None);
    }

    #[test]
    fn empty_and_unicode_string_arrays_remain_valid() {
        let empty: [&str; 0] = [];
        let value = empty.to_variant();
        assert_eq!(value.array_iter_str().unwrap().next(), None);
        assert_eq!(value.array_iter_str().unwrap().next_back(), None);
        let words = ["Foundry", "\u{03b2}eta", "\u{1f525}"];
        let value = words.to_variant();
        assert_eq!(value.array_iter_str().unwrap().collect::<Vec<_>>(), words);
        assert_eq!(value.array_iter_str().unwrap().last(), Some("\u{1f525}"));
    }
}
