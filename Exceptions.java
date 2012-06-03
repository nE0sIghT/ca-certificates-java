/*
 * Copyright (C) 2012 Damien Raude-Morvan <drazzib@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/**
 * Custom exceptions used by {@link UpdateCertificates}
 * 
 * @author Damien Raude-Morvan <drazzib@debian.org>
 */
public class Exceptions {
	
	/**
	 * Data send in stdin is invalid (neither "+" or "-" command).
	 */
	public static class UnknownInput extends Exception {
		private static final long serialVersionUID = 5698253678856993527L;
		public UnknownInput(final String message) {
			super(message);
		}

	}

	/**
	 * Unable to save keystore to provided location. 
	 */
	public static class UnableToSaveKeystore extends Exception {
		private static final long serialVersionUID = 3632154306237688490L;
		public UnableToSaveKeystore(final String message, final Exception e) {
			super(message, e);
		}

	}

	/**
	 * Unable to open keystore from provided location (might be an invalid password
	 * or IO error).
	 */
	public static class InvalidKeystorePassword extends Exception {
		private static final long serialVersionUID = 7004201816889107694L;
		public InvalidKeystorePassword(final String message, final Exception e) {
			super(message, e);
		}

	}

}
