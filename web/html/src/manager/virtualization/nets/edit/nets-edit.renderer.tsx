import * as React from "react";
import { NetsEdit } from "./nets-edit";
import SpaRenderer from "core/spa/spa-renderer";
import { ActionChain } from "components/action-schedule";

type RendererProps = {
  serverId: string;
  netName: string;
  localTime: string;
  timezone: string;
  actionChains: Array<ActionChain>;
};

export const renderer = (id: string, { serverId, actionChains, timezone, localTime, netName }: RendererProps) => {
  SpaRenderer.renderNavigationReact(
    <NetsEdit
      serverId={serverId}
      netName={netName}
      actionChains={actionChains}
      timezone={timezone}
      localTime={localTime}
    />,
    document.getElementById(id)
  );
};
