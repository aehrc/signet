/**
 * Reading an end user's `attributes` record.
 *
 * The record is a free-form blob an operator populates, and two of its keys are
 * load-bearing: `patients` and `encounters` are what the authorisation-time picker
 * offers. Nothing constrains its shape, so both the server that reads those keys and
 * the console that edits them have to be tolerant of a value that is not a list of
 * strings - and they have to be tolerant in the same way, or the console will show
 * an operator a field whose contents the picker then ignores.
 *
 * Author: John Grimes
 */

/**
 * Reads a list of strings out of an attributes record.
 *
 * Anything that is not an array reads as no list at all, and a non-string element is
 * dropped: the alternative is a picker offering `[object Object]` as a patient, or a
 * console textarea showing it.
 *
 * @param attributes - The end user's attributes record.
 * @param name - The key to read.
 * @returns The strings under that key, in the order they are stored.
 * @example
 * attributeStringList({ patients: ["p1", 7] }, "patients"); // ["p1"]
 */
export function attributeStringList(
  attributes: Readonly<Record<string, unknown>>,
  name: string,
): readonly string[] {
  const value = attributes[name];
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}
