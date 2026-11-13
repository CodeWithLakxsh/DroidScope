import { Card, EmptyState, LinkButton, PageHeader } from '@/components/ui';

export default function NotFound() {
  return (
    <>
      <PageHeader title="Page not found" />
      <Card>
        <EmptyState
          title="That page does not exist"
          description="The address may be mistyped, or the resource may have been removed."
          action={<LinkButton to="/" variant="primary">Back to the dashboard</LinkButton>}
        />
      </Card>
    </>
  );
}
