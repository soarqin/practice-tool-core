// #![deny(missing_docs)]

pub mod key;
pub mod widgets;

pub use crossbeam_channel;

rust_i18n::i18n!("locales");

pub fn i18n_set_locale(locale: &str) {
    rust_i18n::set_locale(locale);
}
