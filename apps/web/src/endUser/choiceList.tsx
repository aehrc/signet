/**
 * A list of things to pick one of.
 *
 * Both interaction pages offer a list of buttons - personas to continue as, and patients
 * to choose between - and they are the same control: a menu whose entries are actions
 * rather than links, because choosing one advances a flow rather than navigating.
 *
 * Buttons rather than a select, because the list is short, the choice is consequential,
 * and a select hides the options until it is opened.
 *
 * Author: John Grimes
 */

import type { ReactNode } from "react";

/** One thing that can be picked. */
export interface Choice {
  /** Distinguishes the entry, and is what is passed back when it is chosen. */
  readonly value: string;
  readonly label: string;
  /** Shown beside the label, in a monospace face. Usually an identifier. */
  readonly detail?: string | null;
}

interface ChoiceListProps {
  readonly choices: readonly Choice[];
  readonly disabled: boolean;
  readonly onChoose: (value: string) => void;
  /** Rendered above the list, where it needs explaining. */
  readonly children?: ReactNode;
}

/** A list of choices, each a button. */
export function ChoiceList({
  choices,
  disabled,
  onChoose,
  children,
}: Readonly<ChoiceListProps>) {
  if (choices.length === 0) {
    return null;
  }

  return (
    <div>
      {children}
      <ul className="menu bg-base-100 w-full p-0">
        {choices.map((choice) => (
          <li key={choice.value}>
            <button
              type="button"
              disabled={disabled}
              onClick={() => {
                onChoose(choice.value);
              }}
            >
              <span className="flex-1 text-left">
                {choice.label}
                {choice.detail === undefined ||
                choice.detail === null ? null : (
                  <span className="text-base-content/60 ml-2 font-mono text-xs">
                    {choice.detail}
                  </span>
                )}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
