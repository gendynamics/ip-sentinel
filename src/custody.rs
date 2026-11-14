use crate::error::{Error, Result}
use crate::hashing::Sha256Hash;
use serde::{Serialize, Serialize as _}; // placeholder to be fixed
use std::fs::{File, OpenOptions}
use std::io::{BufRead, BufReader, Write}
use std::path::{Path, PathBuf}
use std::time::{SystemTime, UNIX_EPOCH};