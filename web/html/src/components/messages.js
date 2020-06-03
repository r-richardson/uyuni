// @flow
/* eslint-disable */
import * as React from "react";

type Severity = "info" | "success" | "warning" | "error";

export type MessageType = {
  severity: Severity,
  text: string |
    React.Node |
    Array<React.Node | string> // TODO only for compatibility, deprecate it
}

type Props = {
  /** Message objects to display */
  items: Array<MessageType> | MessageType
}

/**
 * Component to render multiple alert messages.
 *
 * It takes the list of messages in the `items` array.
 * The message objects must be in the following form:
 *
 * ```
 * items = [
 *   {
 *     severity: 'error' | 'warning' | 'success' | 'info',
 *     text: "The message text to display."
 *   },
 *   ...
 * ]
 * ```
 * The `Messages` module additionally offers the `Utils` object that contains
 * helper methods to create a single message object of a specific severity:
 *
 *  - `Utils.info(msg)`
 *  - `Utils.success(msg)`
 *  - `Utils.warning(msg)`
 *  - `Utils.error(msg)`
 *
 * The return value of these methods can be directly fed into the `items` property
 * of the component:
 *
 * ```
 * <Messages items={Utils.info("My info message.")}/>
 * ```
 */
const _classNames = {
    "error": "danger",
    "success": "success",
    "info": "info",
    "warning": "warning",
}

export class Messages extends React.Component<Props> {


    static info(text: string | React.Node): MessageType {
      return msg("info", text);
    }

    static success(text: string | React.Node): MessageType {
      return msg("success", text);
    }

    static error(text: string | React.Node): MessageType {
      return msg("error", text);
    }

    static warning(text: string | React.Node): MessageType {
      return msg("warning", text);
    }

    render() {
        const items: Array<MessageType> = Array.isArray(this.props.items) ? this.props.items : [this.props.items];

        var msgs = items.map((item, index) =>
          <div key={"msg" + index} className={'alert alert-' + _classNames[item.severity]}>
            { Array.isArray(item.text) ? 
              item.text.map(txt => <div>{txt}</div>): item.text }
          </div>
        );

        return (<div key={"messages-pop-up"}>{msgs}</div>);
    }

}

function msg(severityIn: Severity, textIn: string | React.Node | Array<string | React.Node>): MessageType {
    return {severity: severityIn, text: textIn};
}

/**
 * Helper methods to create a single message object of a specific severity
 *
 * The return value of these methods can be directly fed into the `items` property
 * of the `Messages` component.
 */
export const Utils = {
  info: function (textIn: string | React.Node | Array<string | React.Node>): MessageType {
    return msg("info", textIn)
  },
  success: function (textIn: string | React.Node | Array<string | React.Node>): MessageType {
    return msg("success", textIn);
  },
  warning: function (textIn: string | React.Node | Array<string | React.Node>): MessageType {
    return msg("warning", textIn);
  },
  error: function (textIn: string | React.Node | Array<string | React.Node>): MessageType {
    return msg("error", textIn);
  }
}
